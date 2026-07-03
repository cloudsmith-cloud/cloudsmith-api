// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Core.Jobs;

namespace CloudSmith.Api.Relay;

/// <summary>Outcome of a single outbound job.dispatch attempt.</summary>
public enum DispatchStatus
{
    /// <summary>The frame was sent to a connected relay's WebSocket.</summary>
    Dispatched,

    /// <summary>No connected relay matches the job's (site_id, env) — job stays queued.</summary>
    NoRelayConnected,

    /// <summary>A matching relay was found but the socket send failed — job stays queued.</summary>
    SendFailed,
}

/// <summary>Result of a dispatch attempt: status plus the relay chosen (when any).</summary>
public sealed record DispatchResult(DispatchStatus Status, Guid? RelayId = null);

/// <summary>
/// Sends canonical <c>job.dispatch</c> frames (contract §1.1, AB#4839) over the
/// registry WebSocket to the relay selected by strict (site_id, env) routing
/// (contract §5). AB#2961 (API half) + AB#2765.
/// </summary>
public interface IRelayDispatchService
{
    /// <summary>
    /// Attempts to dispatch the job to a connected relay matching
    /// (<paramref name="siteId"/>, <paramref name="env"/>) for <paramref name="orgId"/>.
    /// Never throws for routing/transport failures — the caller leaves the job
    /// queued and the dispatcher rescan/sweeper retries (contract §6.1).
    /// </summary>
    Task<DispatchResult> TryDispatchAsync(
        Guid orgId,
        Guid? siteId,
        string env,
        JobDispatch frame,
        CancellationToken ct = default);
}
