// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.ClusterMgmt.Models;
using CloudSmith.ClusterMgmt.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace CloudSmith.Api.Endpoints;

public static class ClusterEndpoints
{
    public static IEndpointRouteBuilder MapClusterEndpoints(this IEndpointRouteBuilder app)
    {
        var clusters = app.MapGroup("/api/v1/clusters").RequireAuthorization();

        clusters.MapGet("/", async (HttpContext ctx, IClusterService svc, CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            var list = await svc.ListClustersAsync(orgId, ct);
            return Results.Ok(list);
        });

        clusters.MapGet("/{id:guid}", async (Guid id, HttpContext ctx, IClusterService svc, CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            var cluster = await svc.GetClusterAsync(id, orgId, ct);
            return cluster is null ? Results.NotFound() : Results.Ok(cluster);
        });

        clusters.MapPost("/", async (RegisterClusterRequest req, IClusterService svc, CancellationToken ct) =>
        {
            var id = await svc.RegisterClusterAsync(req, ct);
            return Results.Created($"/api/v1/clusters/{id}", new { clusterId = id });
        });

        clusters.MapGet("/{id:guid}/nodes", async (Guid id, HttpContext ctx, INodeService svc, CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            var nodes = await svc.ListNodesAsync(id, orgId, ct);
            return Results.Ok(nodes);
        });

        return app;
    }

    private static bool TryGetOrgId(HttpContext ctx, out Guid orgId)
    {
        if (ctx.Items["OrgId"] is Guid id) { orgId = id; return true; }
        orgId = default;
        return false;
    }
}
