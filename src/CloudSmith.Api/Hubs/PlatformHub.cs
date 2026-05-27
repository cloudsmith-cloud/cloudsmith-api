// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Hubs;

/// <summary>
/// PlatformHub — real-time WebSocket endpoint for the CloudSmith portal and runners.
///
/// Authentication: JWT Bearer (validated by ASP.NET Core middleware before Hub invocation).
/// Authorization: caller must have a valid org_id claim; groups are scoped by org.
///
/// Groups:
///   "org:{orgId}"     — all connections for an organisation (portal, runners)
///   "cluster:{id}"   — connections subscribed to a specific cluster's events
///
/// Client → Server methods:
///   SubscribeCluster(clusterId) — join cluster group for targeted events
///   UnsubscribeCluster(clusterId) — leave cluster group
///
/// Server → Client events (pushed by API services):
///   InventoryUpdated(clusterId, payload) — inventory push from Relay
///   HealthUpdated(clusterId, payload)   — health probe from Relay
///   HardwareUpdated(clusterId, payload) — hardware snapshot from Relay
///   JobProgress(jobId, payload)         — job status update
///
/// AB#1436
/// </summary>
[Authorize]
public sealed class PlatformHub : Hub
{
    private readonly ILogger<PlatformHub> _logger;
    private readonly NpgsqlDataSource _db;

    public PlatformHub(ILogger<PlatformHub> logger, NpgsqlDataSource db)
    {
        _logger = logger;
        _db     = db;
    }

    public override async Task OnConnectedAsync()
    {
        var orgId = GetOrgId();
        if (orgId is null)
        {
            _logger.LogWarning("PlatformHub: connection {ConnectionId} has no org_id claim — disconnecting",
                Context.ConnectionId);
            Context.Abort();
            return;
        }

        // Join org-scoped group so server can broadcast to all org connections.
        await Groups.AddToGroupAsync(Context.ConnectionId, OrgGroup(orgId.Value));
        _logger.LogInformation("PlatformHub: {ConnectionId} joined org group {OrgId}",
            Context.ConnectionId, orgId);

        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var orgId = GetOrgId();
        if (orgId is not null)
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, OrgGroup(orgId.Value));

        _logger.LogInformation("PlatformHub: {ConnectionId} disconnected (error={HasError})",
            Context.ConnectionId, exception is not null);

        await base.OnDisconnectedAsync(exception);
    }

    // -------------------------------------------------------------------------
    // Client-invokable methods
    // -------------------------------------------------------------------------

    /// <summary>Join the cluster-scoped group for targeted cluster events.</summary>
    public async Task SubscribeCluster(string clusterId)
    {
        if (string.IsNullOrWhiteSpace(clusterId))
        {
            _logger.LogWarning("PlatformHub.SubscribeCluster: empty clusterId from {ConnectionId}",
                Context.ConnectionId);
            throw new HubException("clusterId is required.");
        }

        var orgId = GetOrgId();
        if (orgId is null)
            throw new HubException("Cluster not found or access denied.");

        if (!Guid.TryParse(clusterId, out var clusterGuid))
            throw new HubException("Cluster not found or access denied.");

        // Ownership check: verify the cluster belongs to the caller's org.
        await using var conn = await _db.OpenConnectionAsync(Context.ConnectionAborted);
        await using var cmd = new NpgsqlCommand("""
            SELECT 1 FROM cluster_mgmt.clusters WHERE cluster_id = @id AND org_id = @org_id LIMIT 1
            """, conn);
        cmd.Parameters.Add(new NpgsqlParameter("@id", NpgsqlDbType.Uuid) { Value = clusterGuid });
        cmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId.Value });
        var exists = await cmd.ExecuteScalarAsync(Context.ConnectionAborted);

        if (exists is null)
        {
            _logger.LogWarning(
                "PlatformHub.SubscribeCluster: org {OrgId} denied access to cluster {ClusterId} from {ConnectionId}",
                orgId, clusterId, Context.ConnectionId);
            throw new HubException("Cluster not found or access denied.");
        }

        await Groups.AddToGroupAsync(Context.ConnectionId, ClusterGroup(clusterId));
        _logger.LogDebug("PlatformHub: {ConnectionId} subscribed to cluster {ClusterId}",
            Context.ConnectionId, clusterId);
    }

    /// <summary>Leave the cluster-scoped group.</summary>
    public async Task UnsubscribeCluster(string clusterId)
    {
        if (string.IsNullOrWhiteSpace(clusterId)) return;
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, ClusterGroup(clusterId));
        _logger.LogDebug("PlatformHub: {ConnectionId} unsubscribed from cluster {ClusterId}",
            Context.ConnectionId, clusterId);
    }

    // -------------------------------------------------------------------------
    // Group name helpers (used by server-side push services)
    // -------------------------------------------------------------------------

    public static string OrgGroup(Guid orgId)      => $"org:{orgId}";
    public static string ClusterGroup(string id)   => $"cluster:{id}";
    public static string JobGroup(string jobId)    => $"job:{jobId}";

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private Guid? GetOrgId()
    {
        var val = Context.User?.FindFirst("org_id")?.Value;
        return Guid.TryParse(val, out var g) ? g : null;
    }
}
