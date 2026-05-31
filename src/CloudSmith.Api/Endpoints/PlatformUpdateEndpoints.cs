// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using CloudSmith.Api.Authorization;
using CloudSmith.Core.Substrate;
using Microsoft.Extensions.Caching.Memory;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Platform self-update endpoints — AB#1951.
///
/// GET  /api/v1/platform/update/check   — compare running version against latest GitHub release.
/// POST /api/v1/platform/update/apply   — trigger in-place update (PaaS = ACA revision swap; on-prem = SignalR dispatch).
/// </summary>
public static class PlatformUpdateEndpoints
{
    private const string GitHubReleasesUrl =
        "https://api.github.com/repos/cloudsmith-cloud/cloudsmith-api/releases/latest";

    private static readonly string CacheKey = "platform:update:check";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(10);

    // -------------------------------------------------------------------------
    // Response records
    // -------------------------------------------------------------------------

    public sealed record UpdateCheckResponse(
        string CurrentVersion,
        string LatestVersion,
        bool UpdateAvailable,
        string? ReleaseNotesUrl,
        DateTimeOffset CheckedAt);

    public sealed record UpdateApplyResponse(
        string JobId,
        string Status);

    // -------------------------------------------------------------------------
    // Endpoint registration
    // -------------------------------------------------------------------------

    public static IEndpointRouteBuilder MapPlatformUpdateEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/platform/update").WithTags("Platform");

        // GET /api/v1/platform/update/check — AB#1951
        // Returns current version, latest available version from GitHub Releases, and whether an update
        // is available (compared via System.Version.Parse). Result cached 10 minutes.
        // Requires platform:admin — update status is sensitive operational data.
        group.MapGet("/check", async (
            IConfiguration config,
            IMemoryCache cache,
            IHttpClientFactory httpClientFactory,
            CancellationToken ct) =>
        {
            var currentVersion = ResolveCurrentVersion(config);

            string? latestVersion;
            string? releaseNotesUrl;
            string? fetchError;

            if (!cache.TryGetValue(CacheKey, out (string?, string?, string?) cachedResult))
            {
                cachedResult = await FetchLatestReleaseAsync(httpClientFactory, ct);
                cache.Set(CacheKey, cachedResult, CacheTtl);
            }

            (latestVersion, releaseNotesUrl, fetchError) = cachedResult;

            // Compare using System.Version.Parse — update available only when latest > current.
            // Degrade gracefully when GitHub is unreachable or returns an error.
            bool updateAvailable = false;
            if (fetchError is null
                && !string.IsNullOrEmpty(latestVersion)
                && !string.IsNullOrEmpty(currentVersion))
            {
                var normalizedLatest  = NormalizeTag(latestVersion);
                var normalizedCurrent = NormalizeTag(currentVersion);

                if (System.Version.TryParse(normalizedLatest,  out var vLatest)
                    && System.Version.TryParse(normalizedCurrent, out var vCurrent))
                {
                    updateAvailable = vLatest > vCurrent;
                }
                else
                {
                    // Fall back to string inequality when versions are non-semver (e.g. dev/sha tags).
                    updateAvailable = !string.Equals(normalizedCurrent, normalizedLatest,
                        StringComparison.OrdinalIgnoreCase);
                }
            }

            return Results.Ok(new UpdateCheckResponse(
                CurrentVersion:  currentVersion ?? "unknown",
                LatestVersion:   latestVersion  ?? (fetchError is not null ? "unavailable" : "unknown"),
                UpdateAvailable: updateAvailable,
                ReleaseNotesUrl: releaseNotesUrl,
                CheckedAt:       DateTimeOffset.UtcNow));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:admin")))
        .WithSummary("Check for a platform update by comparing the running version against the latest GitHub release. AB#1951.");

        // POST /api/v1/platform/update/apply — AB#1951
        // PaaS: issues an ACA revision swap via Azure Resource Manager (Managed Identity).
        // On-prem: broadcasts a platform:update event to connected runner agents via SignalR.
        // Returns HTTP 202 Accepted with a job ID immediately; actual execution is async.
        group.MapPost("/apply", async (
            ISubstrateAdapter substrate,
            ILogger<PlatformUpdateEndpoints> logger,
            CancellationToken ct) =>
        {
            var jobId = $"upd-{Guid.NewGuid()}";
            try
            {
                logger.LogInformation(
                    "Platform update requested. JobId={JobId} Mode={Mode}", jobId, substrate.Mode);

                // AB#2354 — substrate adapter handles PaaS (ACA revision swap) and on-prem (SignalR dispatch).
                await substrate.TriggerImageUpdateAsync(imageRef: string.Empty, ct);

                return Results.Accepted(
                    uri: $"/api/v1/platform/update/check",
                    value: new UpdateApplyResponse(
                        JobId:  jobId,
                        Status: "Queued"));
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Platform update apply failed. JobId={JobId}", jobId);
                return Results.Json(
                    new { error = "update-failed", jobId, message = ex.Message },
                    statusCode: StatusCodes.Status502BadGateway);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:admin")))
        .WithSummary("Apply a platform update. PaaS: ACA revision swap. On-prem: SignalR dispatch to runner agent. AB#1951.");

        return app;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Resolves the currently running platform version.
    /// Priority: CLOUDSMITH_IMAGE_TAG env var → Platform:Version config key → assembly informational version.
    /// </summary>
    private static string? ResolveCurrentVersion(IConfiguration config)
    {
        var envTag = Environment.GetEnvironmentVariable("CLOUDSMITH_IMAGE_TAG");
        if (!string.IsNullOrWhiteSpace(envTag))
            return envTag;

        var configVersion = config["Platform:Version"];
        if (!string.IsNullOrWhiteSpace(configVersion))
            return configVersion;

        // Fall back to assembly informational version (set at build time via <InformationalVersion>).
        var asm = typeof(PlatformUpdateEndpoints).Assembly;
        var infoVersion = System.Reflection.CustomAttributeExtensions
            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm)
            ?.InformationalVersion;

        // Strip metadata suffix (e.g. "1.2.3+sha.abc") — keep only the version number.
        if (!string.IsNullOrWhiteSpace(infoVersion))
        {
            var plusIdx = infoVersion.IndexOf('+');
            return plusIdx > 0 ? infoVersion[..plusIdx] : infoVersion;
        }

        return null;
    }

    /// <summary>
    /// Fetches the latest release tag and HTML URL from the GitHub Releases API.
    /// Returns (tagName, htmlUrl, null) on success, or (null, null, errorMessage) on failure.
    /// </summary>
    private static async Task<(string? LatestVersion, string? ReleaseNotesUrl, string? Error)>
        FetchLatestReleaseAsync(IHttpClientFactory httpClientFactory, CancellationToken ct)
    {
        try
        {
            using var http = httpClientFactory.CreateClient("github-releases");
            var response = await http.GetAsync(GitHubReleasesUrl, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return (null, null,
                    $"GitHub releases API returned {(int)response.StatusCode}: {response.ReasonPhrase}");
            }

            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(body);

            string? tagName = null;
            string? htmlUrl = null;

            if (doc.RootElement.TryGetProperty("tag_name", out var tagEl))
                tagName = tagEl.GetString();

            if (doc.RootElement.TryGetProperty("html_url", out var urlEl))
                htmlUrl = urlEl.GetString();

            if (string.IsNullOrEmpty(tagName))
                return (null, null, "GitHub releases API response did not include a tag_name.");

            return (tagName, htmlUrl, null);
        }
        catch (Exception ex)
        {
            return (null, null, $"GitHub releases fetch failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Strips a leading "v" prefix from a version tag (e.g. "v1.2.3" → "1.2.3")
    /// so that <see cref="System.Version.TryParse"/> can parse it.
    /// </summary>
    private static string NormalizeTag(string tag) =>
        tag.StartsWith('v') || tag.StartsWith('V') ? tag[1..] : tag;
}
