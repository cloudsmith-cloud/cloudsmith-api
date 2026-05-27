// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Authorization;
using CloudSmith.Api.Services;
using Npgsql;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Published Module Catalog endpoints — proxy the upstream GHCR catalog and merge local install/enable state.
/// AB#1925: GET /api/v1/modules/catalog, POST /api/v1/modules/{id}/install, DELETE /api/v1/modules/{id}.
/// </summary>
public static class ModuleCatalogEndpoints
{
    /// <summary>
    /// Response envelope for the catalog listing.
    /// </summary>
    public sealed record CatalogResponse(
        IReadOnlyList<CatalogItemResponse> Items,
        int TotalCount,
        string FetchedAt);

    /// <summary>
    /// Single catalog entry with merged local install/enable state.
    /// </summary>
    public sealed record CatalogItemResponse(
        string Id,
        string Name,
        string Version,
        string Description,
        string Publisher,
        string GhcrImageRef,
        string ManifestUrl,
        string? SignatureRef,
        bool IsVerified,
        bool IsInstalled,
        bool IsEnabled,
        /// <summary>
        /// True when the module is installed and the catalog version is newer than the installed version.
        /// AB#1959.
        /// </summary>
        bool UpdateAvailable);

    /// <summary>
    /// Request body for POST /api/v1/modules/{id}/install.
    /// Version is optional — omit to default to the latest catalog version.
    /// </summary>
    public sealed record InstallCatalogModuleRequest(string? Version);

    /// <summary>
    /// Response for a successful install request.
    /// </summary>
    public sealed record InstallCatalogModuleResponse(
        string Id,
        string Version,
        string Status);

    public static IEndpointRouteBuilder MapModuleCatalogEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/modules").WithTags("ModuleCatalog");

        // GET /api/v1/modules/catalog
        // Returns the upstream GHCR catalog merged with local installed_modules state.
        group.MapGet("/catalog", async (
            IModuleCatalogService catalog,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            // Fetch upstream catalog (cached 5 min by GhcrModuleCatalogService).
            var catalogEntries = await catalog.ListAsync(ct);

            // Load local install state.
            var installed = await LoadInstalledModulesAsync(db, ct);

            var items = catalogEntries.Select(entry =>
            {
                var hasLocal = installed.TryGetValue(entry.Id, out var local);
                // AB#1959 — updateAvailable: true when installed version < catalog version (semver).
                var updateAvailable = hasLocal
                    && local is not null
                    && IsNewerVersion(entry.Version, local.Version);
                return new CatalogItemResponse(
                    Id:              entry.Id,
                    Name:            entry.Name,
                    Version:         entry.Version,
                    Description:     entry.Description,
                    Publisher:       entry.Publisher,
                    GhcrImageRef:    entry.GhcrImageRef,
                    ManifestUrl:     entry.ManifestUrl,
                    SignatureRef:    entry.SignatureRef,
                    IsVerified:      entry.IsVerified,
                    IsInstalled:     hasLocal,
                    IsEnabled:       hasLocal && local!.IsEnabled,
                    UpdateAvailable: updateAvailable);
            }).ToList();

            var response = new CatalogResponse(
                Items:      items,
                TotalCount: items.Count,
                FetchedAt:  DateTimeOffset.UtcNow.ToString("o"));

            return Results.Ok(response);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("Returns the published module catalog merged with local install/enable state.");

        // POST /api/v1/modules/{id}/install
        // Looks up the catalog entry and upserts into core.installed_modules.
        // Accepts an optional ?version query parameter to pin a specific version (AB#1959).
        // Actual image pull is a future concern — records install intent and returns 202.
        group.MapPost("/{id}/install", async (
            string id,
            string? version,
            InstallCatalogModuleRequest? body,
            IModuleCatalogService catalog,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            // Query parameter ?version takes precedence over request body version field.
            var requestedVersion = version ?? body?.Version;

            // Lookup catalog entry — 404 if module or version not found.
            var entry = await catalog.GetAsync(id, requestedVersion, ct);
            if (entry is null)
            {
                return requestedVersion is not null
                    ? Results.NotFound(new { error = "module-version-not-found", id, version = requestedVersion })
                    : Results.NotFound(new { error = "module-not-found", id });
            }

            const string sql = """
                INSERT INTO core.installed_modules (id, version, is_enabled, installed_at, installed_by)
                VALUES (@id, @version, TRUE, NOW(), 'system')
                ON CONFLICT (id) DO UPDATE
                    SET version      = EXCLUDED.version,
                        installed_at = NOW()
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@id",      entry.Id);
            cmd.Parameters.AddWithValue("@version", entry.Version);
            await cmd.ExecuteNonQueryAsync(ct);

            var result = new InstallCatalogModuleResponse(
                Id:      entry.Id,
                Version: entry.Version,
                Status:  "installing");

            return Results.Accepted($"/api/v1/modules/catalog", result);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Records install intent for a catalog module. Returns 202 Accepted.");

        // DELETE /api/v1/modules/{id}
        // Removes a module from core.installed_modules. Returns 204.
        group.MapDelete("/{id}", async (
            string id,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            const string sql = """
                DELETE FROM core.installed_modules WHERE id = @id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@id", id);
            var rows = await cmd.ExecuteNonQueryAsync(ct);

            return rows == 0
                ? Results.NotFound(new { error = "module-not-installed", id })
                : Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Removes a module from the local installed set. Returns 204.");

        return app;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private sealed record InstalledModuleState(string Id, string Version, bool IsEnabled);

    /// <summary>
    /// Returns true when <paramref name="catalogVersion"/> is strictly greater than
    /// <paramref name="installedVersion"/> using semver-compatible comparison.
    /// Pre-release suffixes (e.g. -rc.1) are stripped before comparison.
    /// AB#1959.
    /// </summary>
    private static bool IsNewerVersion(string catalogVersion, string installedVersion)
    {
        static Version Parse(string v)
        {
            var s = v.StartsWith('v') ? v[1..] : v;
            var dashIdx = s.IndexOf('-');
            if (dashIdx >= 0) s = s[..dashIdx];
            var plusIdx = s.IndexOf('+');
            if (plusIdx >= 0) s = s[..plusIdx];
            return Version.TryParse(s, out var parsed) ? parsed : new Version(0, 0, 0);
        }

        return Parse(catalogVersion) > Parse(installedVersion);
    }

    private static async Task<Dictionary<string, InstalledModuleState>> LoadInstalledModulesAsync(
        NpgsqlDataSource db,
        CancellationToken ct)
    {
        const string sql = """
            SELECT id, version, is_enabled FROM core.installed_modules
            """;

        var result = new Dictionary<string, InstalledModuleState>(StringComparer.OrdinalIgnoreCase);

        await using var conn   = await db.OpenConnectionAsync(ct);
        await using var cmd    = new NpgsqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            var id        = reader.GetString(0);
            var version   = reader.GetString(1);
            var isEnabled = reader.GetBoolean(2);
            result[id]    = new InstalledModuleState(id, version, isEnabled);
        }

        return result;
    }
}
