// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Data;
using System.Security.Claims;
using System.Text.Json;
using CloudSmith.Api.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Platform Management endpoints — Modules listing, install, uninstall, Sites, Audit log query.
/// AB#1640: GET /api/v1/platform/modules — list installed modules for the caller's org.
/// AB#1641: POST /api/v1/platform/modules/install — record a module install (loader applies on restart).
/// AB#1642: DELETE /api/v1/platform/modules/{key} — mark a module for uninstall (loader removes on restart).
/// </summary>
public static class PlatformEndpoints
{
    // Module keys treated as "base" modules — cannot be disabled/uninstalled.
    private static readonly HashSet<string> BaseModulePackageIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "cloudsmith-core",
        "cloudsmith-identity",
        "cloudsmith-secrets",
        "cloudsmith-cluster-mgmt",
    };

    public sealed record InstalledModuleResponse(
        string Key,
        string DisplayName,
        string Version,
        string Status,
        bool IsBase,
        string? InstalledAt,
        string? Description,
        string? HealthMessage);

    public sealed record InstallModuleRequest(string PackageUrl, string PackageId, string DisplayName, string Version, string SdkVersion);

    public sealed record ModulePermissionResponse(string PermissionId, string? Description);

    public sealed record ModuleDependencyResponse(
        string ModuleKey,
        string? DisplayName,
        string RequiredVersion,
        string? InstalledVersion,
        bool Satisfied);

    public sealed record ModuleHealthCheckResponse(string Name, string Status, string? Description);

    public sealed record ModuleHealthResponse(
        string Status,
        string? LastProbe,
        IReadOnlyList<ModuleHealthCheckResponse> Checks);

    public static IEndpointRouteBuilder MapPlatformEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/platform").WithTags("Platform");

        // GET /api/v1/platform/modules — installed modules for the current org.
        group.MapGet("/modules", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                SELECT package_id, display_name, version, status, manifest_json, installed_at
                FROM core.module_registry
                WHERE org_id = @org_id
                ORDER BY display_name
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var results = new List<InstalledModuleResponse>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var packageId = reader.GetString(0);
                var displayName = reader.GetString(1);
                var version = reader.GetString(2);
                var dbStatus = reader.GetString(3);
                var manifestJson = reader.IsDBNull(4) ? null : reader.GetString(4);
                var installedAt = reader.IsDBNull(5) ? (DateTime?)null : reader.GetDateTime(5);

                string? description = null;
                if (!string.IsNullOrEmpty(manifestJson))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(manifestJson);
                        if (doc.RootElement.TryGetProperty("description", out var descProp))
                            description = descProp.GetString();
                    }
                    catch (JsonException) { /* ignore malformed manifest */ }
                }

                results.Add(new InstalledModuleResponse(
                    Key: packageId,
                    DisplayName: displayName,
                    Version: version,
                    Status: MapStatus(dbStatus),
                    IsBase: BaseModulePackageIds.Contains(packageId),
                    InstalledAt: installedAt?.ToString("o"),
                    Description: description,
                    HealthMessage: null));
            }

            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("List installed CloudSmith modules for the caller's organisation.");

        // POST /api/v1/platform/modules/install — AB#1641
        // Records a module install request in core.module_registry with status='installing'.
        // The SDK module loader picks it up at next API startup; this endpoint is the operator-facing
        // record-then-restart flow for Phase IV MVP. Real install pipeline lands later.
        group.MapPost("/modules/install", async (
            InstallModuleRequest request,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var userIdClaim = ctx.User.FindFirstValue("sub");
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Results.Json(new { error = "missing-user-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            if (string.IsNullOrWhiteSpace(request.PackageId)
                || string.IsNullOrWhiteSpace(request.PackageUrl)
                || string.IsNullOrWhiteSpace(request.DisplayName)
                || string.IsNullOrWhiteSpace(request.Version)
                || string.IsNullOrWhiteSpace(request.SdkVersion))
            {
                return Results.Json(new { error = "invalid-request", message = "packageUrl, packageId, displayName, version, and sdkVersion are required." }, statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                INSERT INTO core.module_registry
                    (org_id, package_id, package_url, display_name, version, sdk_version, status, manifest_json, installed_by_user_id, installed_at)
                VALUES
                    (@org_id, @package_id, @package_url, @display_name, @version, @sdk_version, 'installing', @manifest_json::jsonb, @installed_by_user_id, now())
                RETURNING package_id, display_name, version, status, manifest_json, installed_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@package_id", request.PackageId);
            cmd.Parameters.AddWithValue("@package_url", request.PackageUrl);
            cmd.Parameters.AddWithValue("@display_name", request.DisplayName);
            cmd.Parameters.AddWithValue("@version", request.Version);
            cmd.Parameters.AddWithValue("@sdk_version", request.SdkVersion);

            using var manifestDoc = JsonDocument.Parse("{}");
            cmd.Parameters.AddWithValue("@manifest_json", manifestDoc.RootElement.GetRawText());
            cmd.Parameters.AddWithValue("@installed_by_user_id", userId);

            try
            {
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.Json(new { error = "insert-failed" }, statusCode: StatusCodes.Status500InternalServerError);
                }

                var packageId = reader.GetString(0);
                var displayName = reader.GetString(1);
                var version = reader.GetString(2);
                var dbStatus = reader.GetString(3);
                var installedAt = reader.IsDBNull(5) ? (DateTime?)null : reader.GetDateTime(5);

                var response = new InstalledModuleResponse(
                    Key: packageId,
                    DisplayName: displayName,
                    Version: version,
                    Status: MapStatus(dbStatus),
                    IsBase: BaseModulePackageIds.Contains(packageId),
                    InstalledAt: installedAt?.ToString("o"),
                    Description: null,
                    HealthMessage: null);

                return Results.Created($"/api/v1/platform/modules/{packageId}", response);
            }
            catch (PostgresException pex) when (pex.SqlState == "23505")
            {
                return Results.Json(new { error = "module-already-installed", packageId = request.PackageId }, statusCode: StatusCodes.Status409Conflict);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Record a module install for the caller's organisation (loader applies on next API restart).");

        // DELETE /api/v1/platform/modules/{key} — AB#1642
        // Marks a module for uninstall (status='uninstalling'). Base modules cannot be uninstalled.
        // Actual NuGet unload happens at next API restart per the SDK contract.
        group.MapDelete("/modules/{key}", async (
            string key,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            if (BaseModulePackageIds.Contains(key))
            {
                return Results.Json(new { error = "base-module-protected", packageId = key, message = "Base modules cannot be uninstalled." }, statusCode: StatusCodes.Status409Conflict);
            }

            const string sql = """
                UPDATE core.module_registry
                SET status = 'uninstalling'
                WHERE org_id = @org_id AND package_id = @package_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@package_id", key);

            var rows = await cmd.ExecuteNonQueryAsync(ct);
            if (rows == 0)
            {
                return Results.NotFound(new { error = "module-not-found", packageId = key });
            }

            return Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Mark a module for uninstall (loader removes on next API restart).");

        // GET /api/v1/platform/modules/{key}/permissions
        // Reads the module's manifest_json.permissionsRequired array and projects it.
        // Expected manifest shape: { "permissionsRequired": [{ "id": "monitoring:read", "description": "View metrics" }] }
        group.MapGet("/modules/{key}/permissions", async (
            string key,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                SELECT manifest_json
                FROM core.module_registry
                WHERE org_id = @org_id AND package_id = @package_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@package_id", key);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                return Results.NotFound(new { error = "module-not-found", packageId = key });
            }

            var manifestJson = reader.IsDBNull(0) ? null : reader.GetString(0);
            var results = new List<ModulePermissionResponse>();
            if (!string.IsNullOrEmpty(manifestJson))
            {
                try
                {
                    using var doc = JsonDocument.Parse(manifestJson);
                    if (doc.RootElement.TryGetProperty("permissionsRequired", out var permsProp)
                        && permsProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var perm in permsProp.EnumerateArray())
                        {
                            string? id = null;
                            string? description = null;
                            if (perm.ValueKind == JsonValueKind.String)
                            {
                                // Tolerate a flat ["monitoring:read"] shape.
                                id = perm.GetString();
                            }
                            else if (perm.ValueKind == JsonValueKind.Object)
                            {
                                if (perm.TryGetProperty("id", out var idProp))
                                    id = idProp.GetString();
                                if (perm.TryGetProperty("description", out var descProp))
                                    description = descProp.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(id))
                            {
                                results.Add(new ModulePermissionResponse(id!, description));
                            }
                        }
                    }
                }
                catch (JsonException) { /* ignore malformed manifest — return empty */ }
            }

            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("List permissions required by an installed module.");

        // GET /api/v1/platform/modules/{key}/dependencies
        // Reads manifest_json.dependencies and joins against installed modules in the org.
        // Expected shape: { "dependencies": [{ "moduleKey": "cloudsmith-core", "requiredVersion": ">=1.4.0" }] }
        group.MapGet("/modules/{key}/dependencies", async (
            string key,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            await using var conn = await db.OpenConnectionAsync(ct);

            // Load this module's manifest.
            string? manifestJson;
            await using (var cmd = new NpgsqlCommand("""
                SELECT manifest_json
                FROM core.module_registry
                WHERE org_id = @org_id AND package_id = @package_id
                """, conn))
            {
                cmd.Parameters.AddWithValue("@org_id", orgId);
                cmd.Parameters.AddWithValue("@package_id", key);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.NotFound(new { error = "module-not-found", packageId = key });
                }
                manifestJson = reader.IsDBNull(0) ? null : reader.GetString(0);
            }

            // Parse declared dependencies.
            var declared = new List<(string ModuleKey, string RequiredVersion)>();
            if (!string.IsNullOrEmpty(manifestJson))
            {
                try
                {
                    using var doc = JsonDocument.Parse(manifestJson);
                    if (doc.RootElement.TryGetProperty("dependencies", out var depsProp)
                        && depsProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var dep in depsProp.EnumerateArray())
                        {
                            if (dep.ValueKind != JsonValueKind.Object) continue;
                            string? mk = null;
                            string? rv = null;
                            if (dep.TryGetProperty("moduleKey", out var mkProp))
                                mk = mkProp.GetString();
                            if (dep.TryGetProperty("requiredVersion", out var rvProp))
                                rv = rvProp.GetString();
                            if (!string.IsNullOrWhiteSpace(mk))
                            {
                                declared.Add((mk!, rv ?? "*"));
                            }
                        }
                    }
                }
                catch (JsonException) { /* ignore malformed manifest */ }
            }

            if (declared.Count == 0)
            {
                return Results.Ok(Array.Empty<ModuleDependencyResponse>());
            }

            // Look up installed versions for the declared keys.
            var installed = new Dictionary<string, (string DisplayName, string Version)>(StringComparer.OrdinalIgnoreCase);
            await using (var cmd = new NpgsqlCommand("""
                SELECT package_id, display_name, version
                FROM core.module_registry
                WHERE org_id = @org_id AND package_id = ANY(@keys)
                """, conn))
            {
                cmd.Parameters.AddWithValue("@org_id", orgId);
                cmd.Parameters.AddWithValue("@keys", declared.Select(d => d.ModuleKey).Distinct().ToArray());
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    installed[reader.GetString(0)] = (reader.GetString(1), reader.GetString(2));
                }
            }

            var results = new List<ModuleDependencyResponse>(declared.Count);
            foreach (var (mk, rv) in declared)
            {
                installed.TryGetValue(mk, out var info);
                var installedVersion = info.Version; // null when key not in dictionary
                // TODO: full semver range satisfaction (e.g. ">=1.4.0", "^2.0.0") — AB#TBD follow-up.
                // For MVP we treat "installed exists" as satisfied.
                var satisfied = installedVersion != null;
                results.Add(new ModuleDependencyResponse(
                    ModuleKey: mk,
                    DisplayName: info.DisplayName,
                    RequiredVersion: rv,
                    InstalledVersion: installedVersion,
                    Satisfied: satisfied));
            }

            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("List declared dependencies for an installed module and their satisfaction state.");

        // GET /api/v1/platform/modules/{key}/health
        // MVP stub: no real probe infrastructure exists yet. Real per-module health probing
        // (per the SDK contract — IModuleHealthCheck) is a follow-up: AB#TBD.
        // The endpoint still validates the module exists and is scoped to the caller's org.
        group.MapGet("/modules/{key}/health", async (
            string key,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                SELECT 1
                FROM core.module_registry
                WHERE org_id = @org_id AND package_id = @package_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@package_id", key);
            var exists = await cmd.ExecuteScalarAsync(ct);
            if (exists is null)
            {
                return Results.NotFound(new { error = "module-not-found", packageId = key });
            }

            // Stub response — real health requires module-health probing infrastructure
            // (AB#TBD-followup: implement IModuleHealthCheck per SDK contract, collect results
            // via the loader on a schedule, persist to core.module_health_history).
            var response = new ModuleHealthResponse(
                Status: "Unknown",
                LastProbe: null,
                Checks: Array.Empty<ModuleHealthCheckResponse>());

            return Results.Ok(response);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("Module health probe results (MVP stub — real probing is a follow-up).");

        return app;
    }

    /// <summary>
    /// Maps the DB status enum (installing/enabled/degraded/disabled/uninstalling/error) to the
    /// portal-facing status (Installing/Enabled/Failed/Disabled). The portal page's TypeScript
    /// union is Enabled | Disabled | Failed | Installing.
    /// </summary>
    private static string MapStatus(string dbStatus) => dbStatus?.ToLowerInvariant() switch
    {
        "enabled" => "Enabled",
        "disabled" => "Disabled",
        "installing" or "uninstalling" => "Installing",
        "degraded" or "error" => "Failed",
        _ => "Installing",
    };
}
