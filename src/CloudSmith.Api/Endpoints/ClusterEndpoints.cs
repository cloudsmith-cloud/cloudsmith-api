// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

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

        // POST /api/v1/clusters has moved to RelayEndpoints.MapRelayEndpoints — the
        // bridge-aware version supports clusterType + relayId (AB#1670). The route
        // is otherwise functionally equivalent; both flows insert into
        // cluster_mgmt.clusters scoped to the caller's org.

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
