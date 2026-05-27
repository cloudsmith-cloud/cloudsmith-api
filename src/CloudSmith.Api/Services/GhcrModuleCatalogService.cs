// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace CloudSmith.Api.Services;

/// <summary>
/// <see cref="IModuleCatalogService"/> implementation that reads from the
/// GitHub Packages container registry (ghcr.io/cloudsmith-cloud).
/// Caches results for 5 minutes to reduce API calls during browsing.
/// AB#1925.
/// </summary>
public sealed class GhcrModuleCatalogService : IModuleCatalogService
{
    private const string CloudSmithOrg    = "cloudsmith-cloud";
    private const string ModuleLabelKey   = "org.cloudsmith.module";
    private const string ModuleLabelValue = "true";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);

    private readonly HttpClient _http;
    private readonly ILogger<GhcrModuleCatalogService> _logger;

    private IReadOnlyList<ModuleCatalogEntry>? _cached;
    private DateTimeOffset _cacheExpiry = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _cacheLock = new(1, 1);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public GhcrModuleCatalogService(HttpClient httpClient, ILogger<GhcrModuleCatalogService> logger)
    {
        _http   = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger    ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ModuleCatalogEntry>> ListAsync(CancellationToken ct = default)
    {
        var cached = TryGetCache();
        if (cached is not null)
            return cached;

        await _cacheLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            cached = TryGetCache();
            if (cached is not null)
                return cached;

            var entries = await FetchCatalogAsync(ct).ConfigureAwait(false);
            _cached      = entries;
            _cacheExpiry = DateTimeOffset.UtcNow.Add(CacheTtl);
            return entries;
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<ModuleCatalogEntry?> GetAsync(
        string id,
        string? version = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(id);

        var all = await ListAsync(ct).ConfigureAwait(false);
        var matches = all
            .Where(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matches.Count == 0)
            return null;

        if (version is not null)
            return matches.FirstOrDefault(e =>
                string.Equals(e.Version, version, StringComparison.OrdinalIgnoreCase));

        return matches
            .OrderByDescending(e => ParseVersion(e.Version))
            .First();
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private IReadOnlyList<ModuleCatalogEntry>? TryGetCache()
        => _cached is not null && DateTimeOffset.UtcNow < _cacheExpiry ? _cached : null;

    private async Task<IReadOnlyList<ModuleCatalogEntry>> FetchCatalogAsync(CancellationToken ct)
    {
        var packages = await FetchAllPagesAsync(ct).ConfigureAwait(false);
        var entries  = new List<ModuleCatalogEntry>();

        foreach (var pkg in packages)
        {
            var entry = await TryMapPackageAsync(pkg, ct).ConfigureAwait(false);
            if (entry is not null)
                entries.Add(entry);
        }

        return entries
            .OrderBy(e => e.Id, StringComparer.OrdinalIgnoreCase)
            .ToList()
            .AsReadOnly();
    }

    private async Task<List<GhcrPackage>> FetchAllPagesAsync(CancellationToken ct)
    {
        var result = new List<GhcrPackage>();
        var url    = $"/orgs/{CloudSmithOrg}/packages?package_type=container&per_page=100";

        while (url is not null)
        {
            var response = await _http.GetAsync(url, ct).ConfigureAwait(false);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                break;

            // 401/403 means no token or insufficient scope — return empty catalog
            // rather than crashing. The catalog is a best-effort feature when no
            // GITHUB_TOKEN is configured (e.g. air-gapped on-prem installs).
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                _logger.LogWarning(
                    "GHCR catalog fetch returned {StatusCode} — no token or insufficient scope. " +
                    "Set GITHUB_TOKEN env var with read:packages scope to enable the module catalog.",
                    response.StatusCode);
                break;
            }

            response.EnsureSuccessStatusCode();

            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var page = JsonSerializer.Deserialize<List<GhcrPackage>>(body, JsonOptions);
            if (page is not null)
                result.AddRange(page);

            url = ParseNextLink(response.Headers);
        }

        return result;
    }

    private async Task<ModuleCatalogEntry?> TryMapPackageAsync(GhcrPackage pkg, CancellationToken ct)
    {
        var versionsUrl = $"/orgs/{CloudSmithOrg}/packages/container/{Uri.EscapeDataString(pkg.Name)}/versions?per_page=100";
        var response    = await _http.GetAsync(versionsUrl, ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            return null;

        var body     = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var versions = JsonSerializer.Deserialize<List<GhcrPackageVersion>>(body, JsonOptions);

        if (versions is null || versions.Count == 0)
            return null;

        GhcrPackageVersion? candidate    = null;
        string?             candidateTag = null;

        foreach (var ver in versions)
        {
            var tags      = ver.Metadata?.Container?.Tags ?? [];
            var semverTag = tags.FirstOrDefault(IsVersionTag);

            if (semverTag is null)
                continue;

            var labels = ver.Metadata?.Container?.Labels ?? [];
            if (!labels.TryGetValue(ModuleLabelKey, out var labelValue) ||
                !string.Equals(labelValue, ModuleLabelValue, StringComparison.OrdinalIgnoreCase))
                continue;

            candidate    ??= ver;
            candidateTag ??= semverTag;
            break;
        }

        if (candidate is null || candidateTag is null)
            return null;

        var allTags    = versions.SelectMany(v => v.Metadata?.Container?.Tags ?? []).ToHashSet();
        var digest     = candidate.Name;
        var cosignTag  = digest.Replace(":", "-") + ".sig";
        var sigExists  = allTags.Contains(cosignTag);

        var imageRef     = $"ghcr.io/{CloudSmithOrg}/{pkg.Name}:{candidateTag}";
        var signatureRef = sigExists
            ? $"ghcr.io/{CloudSmithOrg}/{pkg.Name}:{cosignTag}"
            : null;

        var labels2     = candidate.Metadata?.Container?.Labels ?? [];
        var displayName = labels2.GetValueOrDefault("org.cloudsmith.module.name")
                          ?? ToDisplayName(pkg.Name);
        var description = labels2.GetValueOrDefault("org.cloudsmith.module.description")
                          ?? pkg.Description
                          ?? string.Empty;
        var publisher   = labels2.GetValueOrDefault("org.cloudsmith.module.publisher")
                          ?? CloudSmithOrg;
        var manifestUrl = labels2.GetValueOrDefault("org.cloudsmith.module.manifest-url")
                          ?? $"https://raw.githubusercontent.com/{CloudSmithOrg}/{pkg.Name}/main/spec.cloudsmith-module.json";

        return new ModuleCatalogEntry(
            Id:           pkg.Name,
            Name:         displayName,
            Version:      candidateTag,
            Description:  description,
            Publisher:    publisher,
            GhcrImageRef: imageRef,
            ManifestUrl:  manifestUrl,
            SignatureRef: signatureRef,
            IsVerified:   sigExists);
    }

    private static string? ParseNextLink(System.Net.Http.Headers.HttpResponseHeaders headers)
    {
        if (!headers.TryGetValues("Link", out var values))
            return null;

        foreach (var header in values)
        {
            foreach (var part in header.Split(','))
            {
                var trimmed   = part.Trim();
                var semicolon = trimmed.IndexOf(';');
                if (semicolon < 0)
                    continue;

                var urlPart = trimmed[..semicolon].Trim().Trim('<', '>');
                var relPart = trimmed[(semicolon + 1)..].Trim();

                if (relPart.Contains("rel=\"next\"", StringComparison.OrdinalIgnoreCase))
                    return urlPart;
            }
        }

        return null;
    }

    private static bool IsVersionTag(string tag)
    {
        if (string.IsNullOrEmpty(tag))
            return false;

        var s = tag.StartsWith('v') ? tag[1..] : tag;
        return s.Length > 0 && char.IsDigit(s[0]);
    }

    private static string ToDisplayName(string packageName)
    {
        var parts = packageName.Split('-', StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', parts.Select(p =>
            p.Length == 0 ? p : char.ToUpperInvariant(p[0]) + p[1..]));
    }

    private static Version ParseVersion(string versionString)
    {
        var s = versionString.StartsWith('v') ? versionString[1..] : versionString;
        var dashIdx = s.IndexOf('-');
        if (dashIdx >= 0) s = s[..dashIdx];
        var plusIdx = s.IndexOf('+');
        if (plusIdx >= 0) s = s[..plusIdx];

        return Version.TryParse(s, out var v) ? v : new Version(0, 0, 0);
    }

    // -------------------------------------------------------------------------
    // Private GitHub API response models
    // -------------------------------------------------------------------------

    private sealed class GhcrPackage
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("description")]
        public string? Description { get; init; }
    }

    private sealed class GhcrPackageVersion
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("metadata")]
        public GhcrVersionMetadata? Metadata { get; init; }
    }

    private sealed class GhcrVersionMetadata
    {
        [JsonPropertyName("container")]
        public GhcrContainerMetadata? Container { get; init; }
    }

    private sealed class GhcrContainerMetadata
    {
        [JsonPropertyName("tags")]
        public List<string> Tags { get; init; } = [];

        [JsonPropertyName("labels")]
        public Dictionary<string, string> Labels { get; init; } = [];
    }
}
