// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

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

    public PlatformHub(ILogger<PlatformHub> logger)
    {
        _logger = logger;
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
            return;
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
