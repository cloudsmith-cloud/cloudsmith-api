// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using CloudSmith.Api.Authorization;
using CloudSmith.Sdk.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Npgsql;

namespace CloudSmith.Api.Endpoints;

public static class ConfigEndpoints
{
    public sealed record ConfigScopeValueResponse(
        string Key,
        string? Value,
        bool IsSecret,
        bool IsOverride,
        string Source,
        string? Description,
        string GroupName,
        string OwningModule);

    public static IEndpointRouteBuilder MapConfigEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/config").WithTags("Config");

        // GET /api/v1/config/variables?module=xxx
        group.MapGet("/variables", async (
            ICloudSmithConfigService svc,
            string? module,
            CancellationToken ct) =>
        {
            var vars = await svc.ListVariablesAsync(module, ct);
            return Results.Ok(vars);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("config:read")))
        .WithSummary("List registered configuration variables");

        // GET /api/v1/config/values/{scopeId} — AB#1650
        // Returns every variable in the org's schema joined with the value (if any) at the given scope.
        // Drives the portal Config Registry value-editor table: shows key, value, isSecret, override flag,
        // source ('scope' when set directly here; 'inherited' when only schema default applies),
        // plus description + grouping for UI rendering.
        group.MapGet("/values/{scopeId:guid}", async (
            Guid scopeId,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            // Guard: scope must belong to the caller's org.
            const string scopeCheckSql = "SELECT 1 FROM config.scopes WHERE scope_id = @scope_id AND org_id = @org_id";
            await using var conn = await db.OpenConnectionAsync(ct);
            await using (var scopeCmd = new NpgsqlCommand(scopeCheckSql, conn))
            {
                scopeCmd.Parameters.AddWithValue("@scope_id", scopeId);
                scopeCmd.Parameters.AddWithValue("@org_id", orgId);
                var hit = await scopeCmd.ExecuteScalarAsync(ct);
                if (hit is null)
                {
                    return Results.NotFound(new { error = "scope-not-found", scopeId });
                }
            }

            // LEFT JOIN so variables with no value at this scope still appear (source='inherited',
            // value falls back to the schema default_value for display).
            const string sql = """
                SELECT
                    vs.key,
                    COALESCE(vv.value, vs.default_value)            AS effective_value,
                    COALESCE(vv.is_secret, vs.is_secret)            AS is_secret,
                    (vv.value_id IS NOT NULL)                       AS is_override,
                    vs.description,
                    vs.group_name,
                    vs.owning_module
                FROM config.variable_schema vs
                LEFT JOIN config.variable_values vv
                    ON vv.variable_id = vs.variable_id AND vv.scope_id = @scope_id
                WHERE (vs.org_id = @org_id OR vs.org_id IS NULL)
                  AND vs.lifecycle_state IN ('active','deprecated')
                ORDER BY vs.group_name, vs.key
                """;

            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@scope_id", scopeId);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var items = new List<ConfigScopeValueResponse>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var key = reader.GetString(0);
                var value = reader.IsDBNull(1) ? null : reader.GetString(1);
                var isSecret = reader.GetBoolean(2);
                var isOverride = reader.GetBoolean(3);
                var description = reader.IsDBNull(4) ? null : reader.GetString(4);
                var groupName = reader.GetString(5);
                var owningModule = reader.GetString(6);

                items.Add(new ConfigScopeValueResponse(
                    Key: key,
                    Value: isSecret ? null : value, // never leak secret values via the list endpoint
                    IsSecret: isSecret,
                    IsOverride: isOverride,
                    Source: isOverride ? "scope" : "inherited",
                    Description: description,
                    GroupName: groupName,
                    OwningModule: owningModule));
            }

            return Results.Ok(items);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("config:read")))
        .WithSummary("List all configuration values at a scope with override + source metadata (AB#1650).");

        // GET /api/v1/config/values/{scopeId}/{key}
        group.MapGet("/values/{scopeId}/{key}", async (
            ICloudSmithConfigService svc,
            string scopeId,
            string key,
            bool effective = true,
            CancellationToken ct = default) =>
        {
            var value = effective
                ? await svc.GetEffectiveValueAsync(scopeId, key, ct)
                : await svc.GetValueAsync(scopeId, key, ct);

            return value is null ? Results.NotFound() : Results.Ok(value);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("config:read")))
        .WithSummary("Get a configuration value at a scope (effective = ancestor-chain resolved)");

        // PUT /api/v1/config/values/{scopeId}/{key}
        group.MapPut("/values/{scopeId}/{key}", async (
            ICloudSmithConfigService svc,
            string scopeId,
            string key,
            ConfigValueWriteRequest body,
            CancellationToken ct) =>
        {
            await svc.SetValueAsync(scopeId, key, body.Value, body.IsSecret, ct);
            return Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("config:write")))
        .WithSummary("Set a configuration value at a specific scope");

        // DELETE /api/v1/config/values/{scopeId}/{key}
        group.MapDelete("/values/{scopeId}/{key}", async (
            ICloudSmithConfigService svc,
            string scopeId,
            string key,
            CancellationToken ct) =>
        {
            await svc.DeleteValueAsync(scopeId, key, ct);
            return Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("config:write")))
        .WithSummary("Delete a configuration value at a specific scope (falls back to ancestor)");

        // GET /api/v1/config/snapshot/{scopeId}
        group.MapGet("/snapshot/{scopeId}", async (
            ICloudSmithConfigService svc,
            string scopeId,
            string? label,
            string? snapshotId,
            CancellationToken ct) =>
        {
            var snapshot = await svc.GetSnapshotAsync(scopeId, label ?? "manual", snapshotId, ct);
            return Results.Ok(snapshot);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("config:read")))
        .WithSummary("Get or create a configuration snapshot at a scope");

        return app;
    }
}

public sealed record ConfigValueWriteRequest(string Value, bool IsSecret = false);
