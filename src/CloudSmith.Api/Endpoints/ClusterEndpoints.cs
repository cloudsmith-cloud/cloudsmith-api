// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using System.Text.Json;
using CloudSmith.Api.Hubs;
using CloudSmith.ClusterMgmt.Services;
using CloudSmith.Core.Jobs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.SignalR;
using Npgsql;

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

        // POST /api/v1/clusters/{id}/nodes — dispatch a runner job to provision a node (AB#1482).
        // Creates a job in core.jobs with job_type = 'provision-node'. The relay picks up
        // the job via GET /lan/v1/agents/{agentId}/jobs and delivers it to the agent.
        clusters.MapPost("/{id:guid}/nodes", async (
            Guid id,
            HttpContext ctx,
            IJobService jobSvc,
            ProvisionNodeRequest body,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            if (!TryGetUserId(ctx, out var userId))  return Results.Unauthorized();

            var payload = JsonSerializer.Serialize(new
            {
                clusterId  = id,
                nodeHostname = body.NodeHostname,
                ipAddress  = body.IpAddress,
                relayId    = body.RelayId,
            });

            var job = await jobSvc.CreateJobAsync(orgId, new CreateJobRequest(
                Module:          "cloudsmith-cluster-mgmt",
                Operation:       "provision-node",
                PayloadJson:     payload,
                CreatedByUserId: userId,
                RunnerId:        null,
                ModuleId:        null), ct);

            return Results.Accepted($"/api/v1/jobs/{job.JobId}", new
            {
                jobId     = job.JobId,
                clusterId = id,
                status    = "Queued",
                statusUrl = $"/api/v1/jobs/{job.JobId}",
            });
        })
        .RequireAuthorization()
        .WithTags("Clusters")
        .WithSummary("Dispatch a runner job to provision a node and add it to the cluster.");

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

        // GET /api/v1/clusters/{id}/health — aggregated health rollup for all nodes in cluster.
        // Pushes the same snapshot to the cluster SignalR group so connected portal clients
        // receive a real-time update on every poll. (AB#1480)
        clusters.MapGet("/{id:guid}/health", async (
            Guid id,
            HttpContext ctx,
            INodeService nodeSvc,
            NpgsqlDataSource db,
            IHubContext<PlatformHub> hub,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();

            // Aggregate health from cluster_mgmt.nodes for the given cluster.
            const string sql = """
                SELECT
                    COUNT(*)                                        AS total,
                    COUNT(*) FILTER (WHERE status = 'online')      AS online,
                    COUNT(*) FILTER (WHERE status = 'offline')     AS offline,
                    COUNT(*) FILTER (WHERE status = 'degraded')    AS degraded,
                    COUNT(*) FILTER (WHERE status = 'maintenance') AS maintenance
                FROM cluster_mgmt.nodes
                WHERE cluster_id = @cluster_id
                  AND org_id     = @org_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@cluster_id", id);
            cmd.Parameters.AddWithValue("@org_id",     orgId);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                return Results.NotFound(new { error = "cluster-not-found" });

            var total       = reader.GetInt64(0);
            var online      = reader.GetInt64(1);
            var offline     = reader.GetInt64(2);
            var degraded    = reader.GetInt64(3);
            var maintenance = reader.GetInt64(4);

            // Overall status: healthy if all online; degraded if any degraded/offline; maintenance if any in maintenance.
            var overallStatus = total == 0   ? "unknown"
                : degraded > 0 || offline > 0 ? "degraded"
                : maintenance > 0              ? "maintenance"
                :                               "healthy";

            var snapshot = new
            {
                clusterId   = id,
                status      = overallStatus,
                totalNodes  = total,
                online,
                offline,
                degraded,
                maintenance,
                asOf        = DateTimeOffset.UtcNow,
            };

            // Push to cluster SignalR group so portal receives real-time health update.
            await hub.Clients
                .Group(PlatformHub.ClusterGroup(id.ToString()))
                .SendAsync("HealthUpdated", id.ToString(), snapshot, ct)
                .ConfigureAwait(false);

            return Results.Ok(snapshot);
        });

        return app;
    }

    private static bool TryGetOrgId(HttpContext ctx, out Guid orgId)
    {
        if (ctx.Items["OrgId"] is Guid id) { orgId = id; return true; }
        orgId = default;
        return false;
    }

    private static bool TryGetUserId(HttpContext ctx, out Guid userId)
    {
        if (ctx.Items["UserId"] is Guid id) { userId = id; return true; }
        var raw = ctx.User.FindFirstValue("sub") ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (Guid.TryParse(raw, out userId)) return true;
        userId = default;
        return false;
    }
}

/// <summary>Request body for POST /clusters/{id}/nodes.</summary>
public sealed record ProvisionNodeRequest(
    string  NodeHostname,
    string? IpAddress,
    Guid?   RelayId);
