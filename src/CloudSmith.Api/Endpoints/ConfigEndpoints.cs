// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Authorization;
using CloudSmith.Sdk.Config;
using Microsoft.AspNetCore.Http.HttpResults;

namespace CloudSmith.Api.Endpoints;

public static class ConfigEndpoints
{
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
