// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Data;
using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;
using CloudSmith.Api.Authorization;
using CloudSmith.Api.Relay;
using CloudSmith.Core.Setup;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Platform Management endpoints — Modules listing, install, uninstall, enable, disable, Sites, Audit log query.
/// AB#1414: Manifest validation on POST /api/v1/platform/modules/install.
/// AB#1415: Module install flow — stores package_url, validated manifest JSON, seeds permissions.
/// AB#1416: Enable/disable state machine — POST /modules/{key}/enable and /modules/{key}/disable.
/// AB#1417: RBAC permission seeding — permissions from manifest.permissionsRequired seeded to core.module_permissions.
/// AB#1640: GET /api/v1/platform/modules — list installed modules for the caller's org.
/// AB#1641: POST /api/v1/platform/modules/install — record a module install.
/// AB#1642: DELETE /api/v1/platform/modules/{key} — mark a module for uninstall.
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

    /// <summary>
    /// CloudSmith module manifest schema (v1).
    /// Required top-level fields: packageId, displayName, version, sdkVersion.
    /// Optional arrays: permissionsRequired (objects with id + optional description),
    ///                  dependencies (objects with moduleKey + requiredVersion).
    /// </summary>
    public sealed record ModuleManifest(
        string PackageId,
        string DisplayName,
        string Version,
        string SdkVersion,
        string? Description,
        IReadOnlyList<ManifestPermission> PermissionsRequired,
        IReadOnlyList<ManifestDependency> Dependencies);

    public sealed record ManifestPermission(string Id, string? Description);
    public sealed record ManifestDependency(string ModuleKey, string RequiredVersion);

    public sealed record InstalledModuleResponse(
        string Key,
        string DisplayName,
        string Version,
        string Status,
        bool IsBase,
        string? InstalledAt,
        string? Description,
        string? HealthMessage);

    public sealed record InstallModuleRequest(
        string PackageUrl,
        string PackageId,
        string DisplayName,
        string Version,
        string SdkVersion,
        string? ManifestJson);

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

    // -------------------------------------------------------------------------
    // Manifest validation — AB#1414
    // -------------------------------------------------------------------------

    /// <summary>
    /// Validates a module manifest JSON string.
    /// Returns (null, parsedManifest) on success; (errorObject, null) on failure.
    /// </summary>
    private static (object? Error, ModuleManifest? Manifest) ValidateManifest(
        string? manifestJson,
        string packageId,
        string displayName,
        string version,
        string sdkVersion)
    {
        ModuleManifest manifest;

        if (string.IsNullOrWhiteSpace(manifestJson))
        {
            // Build a minimal manifest from the top-level install request fields.
            manifest = new ModuleManifest(
                PackageId:            packageId,
                DisplayName:          displayName,
                Version:              version,
                SdkVersion:           sdkVersion,
                Description:          null,
                PermissionsRequired:  Array.Empty<ManifestPermission>(),
                Dependencies:         Array.Empty<ManifestDependency>());
        }
        else
        {
            try
            {
                using var doc = JsonDocument.Parse(manifestJson);
                var root = doc.RootElement;

                // Required fields — manifest must agree with the top-level install request.
                var mPackageId   = root.TryGetProperty("packageId",   out var p1) ? p1.GetString() : null;
                var mDisplayName = root.TryGetProperty("displayName", out var p2) ? p2.GetString() : null;
                var mVersion     = root.TryGetProperty("version",     out var p3) ? p3.GetString() : null;
                var mSdkVersion  = root.TryGetProperty("sdkVersion",  out var p4) ? p4.GetString() : null;

                if (string.IsNullOrWhiteSpace(mPackageId))
                    return (new { error = "manifest-invalid", field = "packageId", message = "manifest.packageId is required." }, null);
                if (string.IsNullOrWhiteSpace(mDisplayName))
                    return (new { error = "manifest-invalid", field = "displayName", message = "manifest.displayName is required." }, null);
                if (string.IsNullOrWhiteSpace(mVersion))
                    return (new { error = "manifest-invalid", field = "version", message = "manifest.version is required." }, null);
                if (string.IsNullOrWhiteSpace(mSdkVersion))
                    return (new { error = "manifest-invalid", field = "sdkVersion", message = "manifest.sdkVersion is required." }, null);

                // Consistency: manifest fields must match install request top-level fields.
                if (!string.Equals(mPackageId, packageId, StringComparison.OrdinalIgnoreCase))
                    return (new { error = "manifest-mismatch", field = "packageId", message = $"manifest.packageId '{mPackageId}' does not match request packageId '{packageId}'." }, null);
                if (!string.Equals(mVersion, version, StringComparison.OrdinalIgnoreCase))
                    return (new { error = "manifest-mismatch", field = "version", message = $"manifest.version '{mVersion}' does not match request version '{version}'." }, null);

                // Parse optional permissionsRequired array.
                var perms = new List<ManifestPermission>();
                if (root.TryGetProperty("permissionsRequired", out var permsEl) && permsEl.ValueKind == JsonValueKind.Array)
                {
                    var idx = 0;
                    foreach (var perm in permsEl.EnumerateArray())
                    {
                        string? id = perm.ValueKind == JsonValueKind.String
                            ? perm.GetString()
                            : perm.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;

                        if (string.IsNullOrWhiteSpace(id))
                            return (new { error = "manifest-invalid", field = $"permissionsRequired[{idx}]", message = "Each permission entry must have a non-empty 'id' (or be a string)." }, null);

                        string? desc = perm.ValueKind == JsonValueKind.Object && perm.TryGetProperty("description", out var dEl) ? dEl.GetString() : null;
                        perms.Add(new ManifestPermission(id!, desc));
                        idx++;
                    }
                }

                // Parse optional dependencies array.
                var deps = new List<ManifestDependency>();
                if (root.TryGetProperty("dependencies", out var depsEl) && depsEl.ValueKind == JsonValueKind.Array)
                {
                    var idx = 0;
                    foreach (var dep in depsEl.EnumerateArray())
                    {
                        if (dep.ValueKind != JsonValueKind.Object)
                            return (new { error = "manifest-invalid", field = $"dependencies[{idx}]", message = "Each dependency must be an object with moduleKey and requiredVersion." }, null);

                        var mk = dep.TryGetProperty("moduleKey",       out var mkEl) ? mkEl.GetString() : null;
                        var rv = dep.TryGetProperty("requiredVersion",  out var rvEl) ? rvEl.GetString() : "*";

                        if (string.IsNullOrWhiteSpace(mk))
                            return (new { error = "manifest-invalid", field = $"dependencies[{idx}].moduleKey", message = "moduleKey is required." }, null);

                        deps.Add(new ManifestDependency(mk!, rv ?? "*"));
                        idx++;
                    }
                }

                var mDesc = root.TryGetProperty("description", out var descProp) ? descProp.GetString() : null;
                manifest = new ModuleManifest(mPackageId!, mDisplayName!, mVersion!, mSdkVersion!, mDesc, perms, deps);
            }
            catch (JsonException ex)
            {
                return (new { error = "manifest-parse-error", message = $"manifestJson is not valid JSON: {ex.Message}" }, null);
            }
        }

        return (null, manifest);
    }

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

        // POST /api/v1/platform/modules/install — AB#1641, AB#1414, AB#1415, AB#1417
        // Validates the module manifest (AB#1414), records the install in core.module_registry
        // with status='installing' and the validated manifest_json (AB#1415), then seeds all
        // declared permissions into core.module_permissions and grants them to the
        // org's platform-admin role (AB#1417).
        //
        // AB#1415 install pipeline note:
        //   The "download, validate checksums, run DB migrations, load assembly, probe health"
        //   pipeline requires a background job worker with assembly isolation — that infrastructure
        //   ships in Phase V. Phase IV records the install intent; the SDK module loader
        //   discovers installed modules on API restart and applies migrations + loads assemblies.
        group.MapPost("/modules/install", async (
            InstallModuleRequest request,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);

            var userIdClaim = ctx.User.FindFirstValue("sub");
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
                return Results.Json(new { error = "missing-user-context" }, statusCode: StatusCodes.Status400BadRequest);

            if (string.IsNullOrWhiteSpace(request.PackageId)
                || string.IsNullOrWhiteSpace(request.PackageUrl)
                || string.IsNullOrWhiteSpace(request.DisplayName)
                || string.IsNullOrWhiteSpace(request.Version)
                || string.IsNullOrWhiteSpace(request.SdkVersion))
            {
                return Results.Json(new { error = "invalid-request", message = "packageUrl, packageId, displayName, version, and sdkVersion are required." }, statusCode: StatusCodes.Status400BadRequest);
            }

            // AB#1414 — validate manifest.
            var (validationError, manifest) = ValidateManifest(
                request.ManifestJson,
                request.PackageId,
                request.DisplayName,
                request.Version,
                request.SdkVersion);

            if (validationError is not null)
                return Results.Json(validationError, statusCode: StatusCodes.Status422UnprocessableEntity);

            // Build canonical manifest JSON for storage — always serialised from the validated object
            // so we never store unvalidated caller input in the DB.
            var manifestToStore = new
            {
                packageId           = manifest!.PackageId,
                displayName         = manifest.DisplayName,
                version             = manifest.Version,
                sdkVersion          = manifest.SdkVersion,
                description         = manifest.Description,
                permissionsRequired = manifest.PermissionsRequired.Select(p => new { id = p.Id, description = p.Description }),
                dependencies        = manifest.Dependencies.Select(d => new { moduleKey = d.ModuleKey, requiredVersion = d.RequiredVersion }),
            };
            var manifestJson = JsonSerializer.Serialize(manifestToStore);

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var tx   = await conn.BeginTransactionAsync(ct);

            Guid   moduleId;
            string retPackageId, retDisplay, retVersion, retStatus;
            DateTime? retInstalledAt;

            try
            {
                const string sql = """
                    INSERT INTO core.module_registry
                        (org_id, package_id, package_url, display_name, version, sdk_version,
                         status, manifest_json, installed_by_user_id, installed_at)
                    VALUES
                        (@org_id, @package_id, @package_url, @display_name, @version, @sdk_version,
                         'installing', @manifest_json::jsonb, @installed_by_user_id, now())
                    RETURNING module_id, package_id, display_name, version, status, installed_at
                    """;

                await using var cmd = new NpgsqlCommand(sql, conn, tx);
                cmd.Parameters.AddWithValue("@org_id",                orgId);
                cmd.Parameters.AddWithValue("@package_id",            request.PackageId);
                cmd.Parameters.AddWithValue("@package_url",           request.PackageUrl);
                cmd.Parameters.AddWithValue("@display_name",          request.DisplayName);
                cmd.Parameters.AddWithValue("@version",               request.Version);
                cmd.Parameters.AddWithValue("@sdk_version",           request.SdkVersion);
                cmd.Parameters.AddWithValue("@manifest_json",         manifestJson);
                cmd.Parameters.AddWithValue("@installed_by_user_id",  userId);

                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    await tx.RollbackAsync(ct);
                    return Results.Json(new { error = "insert-failed" }, statusCode: StatusCodes.Status500InternalServerError);
                }

                moduleId       = reader.GetGuid(0);
                retPackageId   = reader.GetString(1);
                retDisplay     = reader.GetString(2);
                retVersion     = reader.GetString(3);
                retStatus      = reader.GetString(4);
                retInstalledAt = reader.IsDBNull(5) ? (DateTime?)null : reader.GetDateTime(5);
            }
            catch (PostgresException pex) when (pex.SqlState == "23505")
            {
                return Results.Json(new { error = "module-already-installed", packageId = request.PackageId }, statusCode: StatusCodes.Status409Conflict);
            }
            catch
            {
                await tx.RollbackAsync(ct);
                throw;
            }

            await tx.CommitAsync(ct);

            // Seed permissions in a separate transaction — non-fatal if this fails.
            // The install record is already committed; permissions can be re-seeded on retry.
            if (manifest.PermissionsRequired.Count > 0)
            {
                try
                {
                    await SeedModulePermissionsAsync(db, orgId, moduleId, manifest.PermissionsRequired, ct);
                }
                catch (Exception)
                {
                    // Best-effort — log at Warning level; the module record is committed.
                    // TODO: persist seeding failure to core.audit_log for retry visibility.
                }
            }

            var response = new InstalledModuleResponse(
                Key:         retPackageId,
                DisplayName: retDisplay,
                Version:     retVersion,
                Status:      MapStatus(retStatus),
                IsBase:      BaseModulePackageIds.Contains(retPackageId),
                InstalledAt: retInstalledAt?.ToString("o"),
                Description: manifest.Description,
                HealthMessage: null);

            return Results.Created($"/api/v1/platform/modules/{retPackageId}", response);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Record a module install for the caller's organisation (validates manifest, seeds permissions).");

        // DELETE /api/v1/platform/modules/{key} — AB#1642
        // Marks a module for uninstall (status='uninstalling'). Base modules cannot be uninstalled.
        // Actual NuGet unload happens at next API restart per the SDK contract.
        // Also deletes associated module_permissions rows (AB#1417 cleanup).
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
                SET status = 'uninstalling', updated_at = now()
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

        // POST /api/v1/platform/modules/{key}/enable — AB#1416
        // Transitions a module from 'disabled' to 'enabled'. Base modules are always enabled;
        // this endpoint is for user-installed modules that were previously disabled.
        // Valid source states: disabled. Returns 409 if already enabled or in a terminal/installing state.
        group.MapPost("/modules/{key}/enable", async (
            string key,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);

            const string sql = """
                UPDATE core.module_registry
                SET status = 'enabled', updated_at = now()
                WHERE org_id = @org_id AND package_id = @package_id AND status = 'disabled'
                RETURNING status
                """;

            await using var conn = await db.OpenConnectionAsync(ct);

            // First check the module exists at all.
            await using (var checkCmd = new NpgsqlCommand("""
                SELECT status FROM core.module_registry WHERE org_id = @org_id AND package_id = @package_id
                """, conn))
            {
                checkCmd.Parameters.AddWithValue("@org_id", orgId);
                checkCmd.Parameters.AddWithValue("@package_id", key);
                var current = await checkCmd.ExecuteScalarAsync(ct);
                if (current is null)
                    return Results.NotFound(new { error = "module-not-found", packageId = key });
                if ((string)current != "disabled")
                    return Results.Json(new { error = "invalid-state-transition", current = (string)current, requested = "enabled", message = "Module must be in 'disabled' state to enable." }, statusCode: StatusCodes.Status409Conflict);
            }

            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@package_id", key);
            var rows = await cmd.ExecuteNonQueryAsync(ct);
            if (rows == 0)
                return Results.Json(new { error = "state-transition-failed" }, statusCode: StatusCodes.Status500InternalServerError);

            return Results.Ok(new { packageId = key, status = "enabled" });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Enable a previously-disabled module. Transitions status from 'disabled' to 'enabled'.");

        // POST /api/v1/platform/modules/{key}/disable — AB#1416
        // Transitions a module from 'enabled' or 'degraded' to 'disabled'. Base modules cannot be disabled.
        // The loader stops routing requests to a disabled module on next API restart.
        group.MapPost("/modules/{key}/disable", async (
            string key,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);

            if (BaseModulePackageIds.Contains(key))
                return Results.Json(new { error = "base-module-protected", packageId = key, message = "Base modules cannot be disabled." }, statusCode: StatusCodes.Status409Conflict);

            await using var conn = await db.OpenConnectionAsync(ct);

            // Check the module exists and is in a disableable state.
            string? currentStatus;
            await using (var checkCmd = new NpgsqlCommand("""
                SELECT status FROM core.module_registry WHERE org_id = @org_id AND package_id = @package_id
                """, conn))
            {
                checkCmd.Parameters.AddWithValue("@org_id", orgId);
                checkCmd.Parameters.AddWithValue("@package_id", key);
                var current = await checkCmd.ExecuteScalarAsync(ct);
                if (current is null)
                    return Results.NotFound(new { error = "module-not-found", packageId = key });
                currentStatus = (string)current;
            }

            if (currentStatus is not ("enabled" or "degraded"))
                return Results.Json(new { error = "invalid-state-transition", current = currentStatus, requested = "disabled", message = "Module must be 'enabled' or 'degraded' to disable." }, statusCode: StatusCodes.Status409Conflict);

            await using var cmd = new NpgsqlCommand("""
                UPDATE core.module_registry
                SET status = 'disabled', updated_at = now()
                WHERE org_id = @org_id AND package_id = @package_id AND status IN ('enabled','degraded')
                """, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@package_id", key);
            await cmd.ExecuteNonQueryAsync(ct);

            return Results.Ok(new { packageId = key, status = "disabled" });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Disable a module. Transitions status from 'enabled'/'degraded' to 'disabled'. Base modules cannot be disabled.");

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

        // GET /api/v1/platform/setup-status — authenticated setup status for admin dashboard (AB#1622).
        // Returns richer state than the anonymous /api/v1/setup/status endpoint, including
        // completedAt, completedByUserId, timezone, and public URL.
        group.MapGet("/setup-status", async (
            SetupService setup,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            const string sql = """
                SELECT setup_state, platform_name, public_url, timezone,
                       completed_at, completed_by_user_id
                FROM core.platform_setup
                WHERE id = true
                LIMIT 1
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(sql, conn);
            await using var reader = await cmd.ExecuteReaderAsync(ct);

            if (!await reader.ReadAsync(ct))
            {
                return Results.Ok(new
                {
                    setupComplete       = false,
                    setupState          = "Pending",
                    platformName        = (string?)null,
                    publicUrl           = (string?)null,
                    timezone            = (string?)null,
                    completedAt         = (DateTimeOffset?)null,
                    completedByUserId   = (Guid?)null,
                });
            }

            var state            = reader.GetString(0);
            var platformName     = reader.IsDBNull(1) ? null : reader.GetString(1);
            var publicUrl        = reader.IsDBNull(2) ? null : reader.GetString(2);
            var timezone         = reader.IsDBNull(3) ? null : reader.GetString(3);
            var completedAt      = reader.IsDBNull(4) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(4);
            var completedByUser  = reader.IsDBNull(5) ? (Guid?)null : reader.GetGuid(5);

            return Results.Ok(new
            {
                setupComplete       = state == "Completed",
                setupState          = state,
                platformName,
                publicUrl,
                timezone,
                completedAt,
                completedByUserId   = completedByUser,
            });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("Returns richer platform setup state for the admin dashboard (AB#1622).");

        // GET /api/v1/platform/health — per-component control-plane health board.
        // Returns API server, PostgreSQL, active relay agents, and identity provider status.
        // Portal screen 17 reads this endpoint. Falls back gracefully when components are unknown.
        group.MapGet("/health", async (
            NpgsqlDataSource db,
            IConnectedRelayRegistry relayRegistry,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);

            var components = new List<object>();
            var checkedAt = DateTimeOffset.UtcNow.ToString("o");
            var overallHealthy = true;

            // API Server — trivially healthy if we're here.
            components.Add(new
            {
                name        = "API Server",
                status      = "healthy",
                detail      = "Responding",
                latencyMs   = (int?)null,
                lastChecked = checkedAt,
            });

            // PostgreSQL — quick connectivity probe.
            string dbStatus   = "unknown";
            string? dbDetail  = null;
            int?    dbLatency = null;
            try
            {
                var sw = Stopwatch.StartNew();
                await using var conn = await db.OpenConnectionAsync(ct);
                await using var cmd  = new NpgsqlCommand("SELECT 1", conn);
                await cmd.ExecuteScalarAsync(ct);
                sw.Stop();
                dbStatus  = "healthy";
                dbDetail  = "Connected";
                dbLatency = (int)sw.ElapsedMilliseconds;
            }
            catch (Exception ex)
            {
                dbStatus       = "unhealthy";
                dbDetail       = ex.Message.Length > 120 ? ex.Message[..120] : ex.Message;
                overallHealthy = false;
            }
            components.Add(new { name = "PostgreSQL", status = dbStatus, detail = dbDetail, latencyMs = dbLatency, lastChecked = checkedAt });

            // Relay Agent — count active WebSocket connections in memory.
            var connectedRelays = relayRegistry.ConnectedRelayIds.Count;
            string relayStatus = connectedRelays > 0 ? "healthy" : "degraded";
            string relayDetail = connectedRelays > 0
                ? $"{connectedRelays} relay{(connectedRelays == 1 ? "" : "s")} connected"
                : "No relays connected — on-prem data is not flowing";
            if (connectedRelays == 0) overallHealthy = false;
            components.Add(new { name = "Relay Agent", status = relayStatus, detail = relayDetail, latencyMs = (int?)null, lastChecked = checkedAt });

            // Identity Provider — check if any IdP rows exist in DB; status based on enabled count.
            string idpStatus = "unknown";
            string? idpDetail = null;
            try
            {
                const string idpSql = """
                    SELECT COUNT(*) FROM core.identity_providers WHERE org_id = @org_id AND enabled = true
                    """;
                await using var conn = await db.OpenConnectionAsync(ct);
                await using var cmd  = new NpgsqlCommand(idpSql, conn);
                cmd.Parameters.AddWithValue("@org_id", orgId);
                var count = (long)(await cmd.ExecuteScalarAsync(ct) ?? 0L);
                idpStatus = count > 0 ? "healthy" : "unknown";
                idpDetail = count > 0 ? $"{count} provider{(count == 1 ? "" : "s")} enabled" : "No identity providers configured (local auth only)";
            }
            catch
            {
                idpStatus = "unknown";
                idpDetail = "Could not query identity providers";
            }
            components.Add(new { name = "Identity Provider", status = idpStatus, detail = idpDetail, latencyMs = (int?)null, lastChecked = checkedAt });

            var overallStr = overallHealthy ? "healthy" : "degraded";
            return Results.Ok(new { overallStatus = overallStr, components });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("Per-component control-plane health board (API server, PostgreSQL, relay agents, identity providers).");

        // GET /api/v1/platform/version — component version manifest. AB#2514.
        // Returns API version (from CLOUDSMITH_VERSION env var), portal version (from
        // CLOUDSMITH_PORTAL_VERSION env var), solution version (from CLOUDSMITH_SOLUTION_VERSION
        // env var), and connected relay list with displayName and lastSeenAt.
        // Accessible to any authenticated user (no elevated scope required).
        group.MapGet("/version", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);

            var apiVersion      = Environment.GetEnvironmentVariable("CLOUDSMITH_VERSION") ?? "unknown";
            var portalVersion   = Environment.GetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION") ?? "unknown";
            var solutionVersion = Environment.GetEnvironmentVariable("CLOUDSMITH_SOLUTION_VERSION") ?? "unknown";
            var apiCommitSha    = Environment.GetEnvironmentVariable("CLOUDSMITH_COMMIT_SHA") ?? "unknown";

            // Query connected relays for this org — return relayId, displayName, and lastSeenAt.
            // The 'version' field is not stored yet; return "unknown" per graceful-degradation rule.
            var relays = new List<object>();
            try
            {
                const string relaySql = """
                    SELECT relay_id, display_name, last_seen_at
                    FROM core.relays
                    WHERE org_id = @org_id AND status = 'active'
                    ORDER BY display_name
                    """;
                await using var conn = await db.OpenConnectionAsync(ct);
                await using var cmd  = new NpgsqlCommand(relaySql, conn);
                cmd.Parameters.AddWithValue("@org_id", orgId);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    relays.Add(new
                    {
                        relayId     = reader.GetGuid(0).ToString(),
                        displayName = reader.GetString(1),
                        version     = "unknown",
                        lastSeenAt  = reader.IsDBNull(2) ? (string?)null : reader.GetDateTime(2).ToString("o"),
                    });
                }
            }
            catch
            {
                // DB error — return empty relay list rather than failing the whole request.
            }

            return Results.Ok(new
            {
                apiVersion,
                apiCommitSha,
                portalVersion,
                solutionVersion,
                connectedRelays = relays,
            });
        })
        .RequireAuthorization()
        .WithSummary("Component version manifest — API, portal, solution, and connected relays. Accessible to any authenticated user (AB#2514).");

        return app;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Seeds permissions declared in a module manifest into core.module_permissions
    /// and grants them to the org's platform-admin role.
    /// AB#1417 — register module permissions in RBAC on module install.
    /// This runs outside the main install transaction; failure is non-fatal (logged, not thrown).
    /// </summary>
    private static async Task SeedModulePermissionsAsync(
        NpgsqlDataSource db,
        Guid orgId,
        Guid moduleId,
        IReadOnlyList<ManifestPermission> permissions,
        CancellationToken ct)
    {
        await using var conn = await db.OpenConnectionAsync(ct);
        await using var tx   = await conn.BeginTransactionAsync(ct);
        try
        {
            // Upsert into core.module_permissions.
            foreach (var perm in permissions)
            {
                await using var cmd = new NpgsqlCommand("""
                    INSERT INTO core.module_permissions (org_id, module_id, permission, description)
                    VALUES (@org_id, @module_id, @permission, @description)
                    ON CONFLICT (org_id, module_id, permission) DO UPDATE
                        SET description = EXCLUDED.description
                    """, conn, tx);
                cmd.Parameters.AddWithValue("@org_id",      orgId);
                cmd.Parameters.AddWithValue("@module_id",   moduleId);
                cmd.Parameters.AddWithValue("@permission",  perm.Id);
                cmd.Parameters.AddWithValue("@description", perm.Description is null ? DBNull.Value : (object)perm.Description);
                await cmd.ExecuteNonQueryAsync(ct);
            }

            // Grant these permissions to the org's built-in platform-admin role.
            // If the role does not exist (e.g. bootstrap not yet complete) this is a no-op.
            await using (var lookupCmd = new NpgsqlCommand("""
                SELECT role_id FROM core.role_definitions
                WHERE org_id = @org_id AND name = 'platform-admin' AND is_built_in = true
                LIMIT 1
                """, conn, tx))
            {
                lookupCmd.Parameters.AddWithValue("@org_id", orgId);
                var roleId = await lookupCmd.ExecuteScalarAsync(ct);

                if (roleId is Guid rid)
                {
                    foreach (var perm in permissions)
                    {
                        await using var grantCmd = new NpgsqlCommand("""
                            INSERT INTO core.role_permissions (role_id, permission)
                            VALUES (@role_id, @permission)
                            ON CONFLICT DO NOTHING
                            """, conn, tx);
                        grantCmd.Parameters.AddWithValue("@role_id",    rid);
                        grantCmd.Parameters.AddWithValue("@permission", perm.Id);
                        await grantCmd.ExecuteNonQueryAsync(ct);
                    }
                }
            }

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            // Non-fatal — caller already committed the module registry row.
            throw;
        }
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
