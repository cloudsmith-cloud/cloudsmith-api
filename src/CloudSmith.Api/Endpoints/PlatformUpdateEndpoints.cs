// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.AppContainers;
using CloudSmith.Api.Authorization;
using CloudSmith.Api.Hubs;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Memory;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Platform self-update endpoints — AB#1951.
///
/// GET  /api/v1/platform/updates/check   — AB#1952: compare running version against latest GHCR digest.
/// PUT  /api/v1/platform/updates/apply   — AB#1953: trigger update (PaaS = ACA revision swap; on-prem = SignalR dispatch).
/// </summary>
public static class PlatformUpdateEndpoints
{
    private const string GhcrManifestUrl =
        "https://ghcr.io/v2/cloudsmith-cloud/cloudsmith-api/manifests/latest";

    private const string GhcrManifestAccept =
        "application/vnd.oci.image.index.v1+json";

    private static readonly string CacheKey = "platform:update:check";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(15);

    // -------------------------------------------------------------------------
    // Response records
    // -------------------------------------------------------------------------

    public sealed record UpdateCheckResponse(
        string CurrentVersion,
        string LatestVersion,
        string LatestDigest,
        bool UpdateAvailable,
        DateTimeOffset CheckedAt);

    public sealed record UpdateApplyResponse(
        Guid UpdateId,
        string Status,
        string Message);

    // -------------------------------------------------------------------------
    // Endpoint registration
    // -------------------------------------------------------------------------

    public static IEndpointRouteBuilder MapPlatformUpdateEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/platform/updates").WithTags("Platform");

        // GET /api/v1/platform/updates/check — AB#1952
        // Returns the currently running image tag and the latest GHCR digest.
        // GHCR response is cached 15 minutes. No auth required (read-only status).
        group.MapGet("/check", async (
            IMemoryCache cache,
            IHttpClientFactory httpClientFactory,
            CancellationToken ct) =>
        {
            var currentVersion = ResolveCurrentVersion();

            // Attempt to get the latest digest from GHCR (or cache).
            var cached = await cache.GetOrCreateAsync(CacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = CacheTtl;
                return await FetchLatestGhcrDigestAsync(httpClientFactory, ct);
            });

            var (latestVersion, latestDigest, fetchError) = cached ?? (null, null, "cache miss");

            if (fetchError is not null)
            {
                // Surface the error so callers know the check could not complete.
                return Results.Json(
                    new { error = "ghcr-fetch-failed", message = fetchError },
                    statusCode: StatusCodes.Status502BadGateway);
            }

            var updateAvailable = !string.IsNullOrEmpty(latestVersion)
                && !string.IsNullOrEmpty(currentVersion)
                && !string.Equals(currentVersion, latestVersion, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(currentVersion, latestDigest, StringComparison.OrdinalIgnoreCase);

            return Results.Ok(new UpdateCheckResponse(
                CurrentVersion:  currentVersion ?? "unknown",
                LatestVersion:   latestVersion  ?? "unknown",
                LatestDigest:    latestDigest   ?? "unknown",
                UpdateAvailable: updateAvailable,
                CheckedAt:       DateTimeOffset.UtcNow));
        })
        .AllowAnonymous()
        .WithSummary("Check for a platform update by comparing the running image tag against the latest GHCR digest. AB#1952.");

        // PUT /api/v1/platform/updates/apply — AB#1953
        // PaaS: issues an ACA revision swap via Azure Resource Manager (Managed Identity).
        // On-prem: broadcasts a platform:update event to connected runner agents via SignalR.
        group.MapPut("/apply", async (
            IHubContext<PlatformHub> hub,
            IHttpClientFactory httpClientFactory,
            ILogger<PlatformUpdateEndpoints> logger,
            CancellationToken ct) =>
        {
            var updateId = Guid.NewGuid();
            var deploymentModel = (Environment.GetEnvironmentVariable("CLOUDSMITH_DEPLOYMENT_MODEL")
                ?? string.Empty).Trim().ToLowerInvariant();

            if (deploymentModel == "paas")
            {
                // PaaS path: swap ACA revision via ARM API using DefaultAzureCredential
                // (the ACA managed identity has ACA Contributor on the RG).
                var (success, message) = await ApplyAcaUpdateAsync(logger, ct);

                if (!success)
                {
                    return Results.Json(
                        new { error = "aca-update-failed", message },
                        statusCode: StatusCodes.Status502BadGateway);
                }

                return Results.Accepted($"/api/v1/platform/updates/check",
                    new UpdateApplyResponse(
                        UpdateId: updateId,
                        Status:   "Accepted",
                        Message:  "ACA revision swap initiated"));
            }
            else
            {
                // On-prem path: broadcast to all runner agents connected to the platform group.
                await hub.Clients
                    .Group("platform:runners")
                    .SendAsync("platform:update", new { updateId, requestedAt = DateTimeOffset.UtcNow }, ct);

                logger.LogInformation(
                    "Platform update dispatched to on-prem runner group. UpdateId={UpdateId}", updateId);

                return Results.Accepted($"/api/v1/platform/updates/check",
                    new UpdateApplyResponse(
                        UpdateId: updateId,
                        Status:   "Accepted",
                        Message:  "Update dispatched to on-prem agent"));
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:admin")))
        .WithSummary("Apply a platform update. PaaS: ACA revision swap. On-prem: SignalR dispatch to runner agent. AB#1953.");

        return app;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Resolves the currently running image version from the CLOUDSMITH_IMAGE_TAG env var,
    /// falling back to the machine name (in ACA this is the revision name prefix).
    /// </summary>
    private static string? ResolveCurrentVersion()
    {
        var tag = Environment.GetEnvironmentVariable("CLOUDSMITH_IMAGE_TAG");
        if (!string.IsNullOrWhiteSpace(tag))
            return tag;

        // Fallback: use the hostname which in ACA contains the revision name.
        return Environment.MachineName;
    }

    /// <summary>
    /// Fetches the Docker-Content-Digest header from the GHCR manifests endpoint for
    /// <c>cloudsmith-api:latest</c>. Public images require no auth.
    /// Returns (digest, digest, null) on success, or (null, null, errorMessage) on failure.
    /// </summary>
    private static async Task<(string? LatestVersion, string? LatestDigest, string? Error)>
        FetchLatestGhcrDigestAsync(IHttpClientFactory httpClientFactory, CancellationToken ct)
    {
        try
        {
            using var http = httpClientFactory.CreateClient("ghcr-update");
            http.DefaultRequestHeaders.Add("Accept", GhcrManifestAccept);

            var response = await http.GetAsync(GhcrManifestUrl, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return (null, null,
                    $"GHCR manifest request returned {(int)response.StatusCode}: {response.ReasonPhrase}");
            }

            // The digest is the authoritative identifier for the manifest.
            string? digest = null;
            if (response.Headers.TryGetValues("Docker-Content-Digest", out var digestValues))
                digest = digestValues.FirstOrDefault();

            if (string.IsNullOrEmpty(digest))
            {
                // Fall back to parsing the body for the config digest.
                var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("manifests", out var manifests)
                        && manifests.GetArrayLength() > 0)
                    {
                        digest = manifests[0]
                            .TryGetProperty("digest", out var d) ? d.GetString() : null;
                    }
                }
                catch (JsonException) { /* ignore */ }
            }

            if (string.IsNullOrEmpty(digest))
                return (null, null, "GHCR response did not include a Docker-Content-Digest header or manifest digest.");

            return (digest, digest, null);
        }
        catch (Exception ex)
        {
            return (null, null, $"GHCR fetch failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Triggers an ACA image update for <c>ca-cloudsmith-api</c> using DefaultAzureCredential
    /// against the ARM SDK. Expects the env vars AZURE_SUBSCRIPTION_ID and
    /// CLOUDSMITH_ACA_RESOURCE_GROUP to be set at deploy time.
    /// Returns (true, message) on success, (false, errorMessage) on failure.
    /// </summary>
    private static async Task<(bool Success, string Message)> ApplyAcaUpdateAsync(
        ILogger logger,
        CancellationToken ct)
    {
        try
        {
            var subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID");
            var resourceGroup  = Environment.GetEnvironmentVariable("CLOUDSMITH_ACA_RESOURCE_GROUP");

            if (string.IsNullOrWhiteSpace(subscriptionId) || string.IsNullOrWhiteSpace(resourceGroup))
            {
                return (false,
                    "AZURE_SUBSCRIPTION_ID and CLOUDSMITH_ACA_RESOURCE_GROUP must be set for PaaS update.");
            }

            var credential = new DefaultAzureCredential();
            var armClient  = new ArmClient(credential);

            // Build the resource ID for ca-cloudsmith-api and locate it.
            const string apiAppName = "ca-cloudsmith-api";
            var appId = ContainerAppResource.CreateResourceIdentifier(
                subscriptionId, resourceGroup, apiAppName);

            var apiApp = armClient.GetContainerAppResource(appId);

            // Fetch the current data so we can issue a no-op patch that forces a
            // new revision to be created against the same :latest tag.
            var current = await apiApp.GetAsync(ct).ConfigureAwait(false);
            var patchData = current.Value.Data;

            // Issue the update — ACA creates a new revision that re-resolves :latest.
            var updateOp = await apiApp.UpdateAsync(
                Azure.WaitUntil.Started,
                patchData,
                ct).ConfigureAwait(false);

            logger.LogInformation(
                "ACA revision swap initiated for {AppName}. OperationId={OperationId}",
                apiAppName, updateOp.Id);

            return (true, "ACA revision swap initiated");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "ACA update failed");
            return (false, $"ACA update failed: {ex.Message}");
        }
    }
}
