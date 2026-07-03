// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

namespace CloudSmith.Api.Relay;

/// <summary>
/// A relay row eligible for dispatch consideration, as loaded from core.relays.
/// </summary>
/// <param name="RelayId">core.relays.relay_id.</param>
/// <param name="SiteId">The relay's site scope. Null = not routable.</param>
/// <param name="Env">The relay's environment scope (never null — NOT NULL DEFAULT 'default').</param>
/// <param name="LastSeenAt">Tie-break: most recently seen wins.</param>
public sealed record RelayCandidate(Guid RelayId, Guid? SiteId, string Env, DateTimeOffset? LastSeenAt);

/// <summary>
/// Pure (site_id, env) routing rule per the frozen contract
/// (cloudsmith-internal design/api-surface/job-dispatch-contract.md §5, AB#2765):
/// a job is routable to a Relay iff <c>job.site_id = relay.site_id AND job.env = relay.env</c>.
/// No cross-site or cross-env fallback, ever. Among multiple matching connected
/// relays, most recent last_seen_at wins. A job with site_id IS NULL never routes.
/// </summary>
public static class RelayRouting
{
    /// <summary>
    /// Selects the relay to dispatch to, or null when no connected relay matches.
    /// </summary>
    /// <param name="jobSiteId">The job's site scope; null is never routable (contract §5).</param>
    /// <param name="jobEnv">The job's environment scope.</param>
    /// <param name="candidates">Non-revoked relay rows for the job's org.</param>
    /// <param name="connectedRelayIds">Relay IDs with a currently-open WebSocket.</param>
    public static Guid? SelectRelay(
        Guid? jobSiteId,
        string jobEnv,
        IEnumerable<RelayCandidate> candidates,
        IReadOnlyCollection<string> connectedRelayIds)
    {
        if (jobSiteId is null)
            return null;

        var connected = new HashSet<string>(connectedRelayIds, StringComparer.OrdinalIgnoreCase);

        return candidates
            .Where(c => c.SiteId == jobSiteId
                     && string.Equals(c.Env, jobEnv, StringComparison.Ordinal)
                     && connected.Contains(c.RelayId.ToString()))
            .OrderByDescending(c => c.LastSeenAt ?? DateTimeOffset.MinValue)
            .Select(c => (Guid?)c.RelayId)
            .FirstOrDefault();
    }
}
