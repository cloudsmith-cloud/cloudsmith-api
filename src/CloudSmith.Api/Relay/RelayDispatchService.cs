// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Net.WebSockets;
using System.Text.Json;
using CloudSmith.Core.Jobs;
using Npgsql;

namespace CloudSmith.Api.Relay;

/// <inheritdoc cref="IRelayDispatchService"/>
public sealed class RelayDispatchService : IRelayDispatchService
{
    /// <summary>
    /// Wire options for the canonical frames: camelCase property names with the
    /// <c>$type</c> discriminator emitted by serializing as the <see cref="JobFrame"/>
    /// base type (contract §1, AB#4839).
    /// </summary>
    private static readonly JsonSerializerOptions WireJsonOptions = new(JsonSerializerDefaults.Web);

    private readonly NpgsqlDataSource _db;
    private readonly IConnectedRelayRegistry _registry;
    private readonly ILogger<RelayDispatchService> _logger;

    public RelayDispatchService(
        NpgsqlDataSource db,
        IConnectedRelayRegistry registry,
        ILogger<RelayDispatchService> logger)
    {
        _db       = db;
        _registry = registry;
        _logger   = logger;
    }

    /// <summary>
    /// Serializes a frame with the <c>$type</c> discriminator. The frame MUST be
    /// serialized as the <see cref="JobFrame"/> base type — serializing the derived
    /// type directly would omit the discriminator.
    /// </summary>
    public static byte[] SerializeFrame(JobFrame frame) =>
        JsonSerializer.SerializeToUtf8Bytes(frame, WireJsonOptions);

    public async Task<DispatchResult> TryDispatchAsync(
        Guid orgId,
        Guid? siteId,
        string env,
        JobDispatch frame,
        CancellationToken ct = default)
    {
        // Contract §5: a job with site_id IS NULL is never routable to a Relay.
        if (siteId is null)
        {
            _logger.LogDebug("Job {JobId}: site_id is null — not routable to any relay", frame.JobId);
            return new DispatchResult(DispatchStatus.NoRelayConnected);
        }

        var candidates = await LoadCandidatesAsync(orgId, siteId.Value, env, ct);
        var relayId    = RelayRouting.SelectRelay(siteId, env, candidates, _registry.ConnectedRelayIds);

        if (relayId is null)
        {
            _logger.LogInformation(
                "Job {JobId}: no connected relay matches (site {SiteId}, env {Env}) — staying queued",
                frame.JobId, siteId, env);
            return new DispatchResult(DispatchStatus.NoRelayConnected);
        }

        var socket = _registry.TryGet(relayId.Value.ToString());
        if (socket is null || socket.State != WebSocketState.Open)
        {
            // Raced with a disconnect between selection and send.
            _logger.LogInformation(
                "Job {JobId}: relay {RelayId} disconnected before send — staying queued",
                frame.JobId, relayId);
            return new DispatchResult(DispatchStatus.NoRelayConnected, relayId);
        }

        try
        {
            var payload = SerializeFrame(frame);
            await socket.SendAsync(payload, WebSocketMessageType.Text, endOfMessage: true, ct);
            _logger.LogInformation(
                "Job {JobId}: job.dispatch sent to relay {RelayId} (site {SiteId}, env {Env})",
                frame.JobId, relayId, siteId, env);
            return new DispatchResult(DispatchStatus.Dispatched, relayId);
        }
        catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException or InvalidOperationException)
        {
            _logger.LogWarning(ex,
                "Job {JobId}: WebSocket send to relay {RelayId} failed — staying queued",
                frame.JobId, relayId);
            return new DispatchResult(DispatchStatus.SendFailed, relayId);
        }
    }

    private async Task<IReadOnlyList<RelayCandidate>> LoadCandidatesAsync(
        Guid orgId, Guid siteId, string env, CancellationToken ct)
    {
        // Strict (site_id, env) equality — no fallback (contract §5). Uses
        // idx_relays_site_env_last_seen (M20260703101). Tie-break last_seen_at DESC.
        const string sql = """
            SELECT relay_id, site_id, env, last_seen_at
            FROM core.relays
            WHERE org_id = @org_id
              AND site_id = @site_id
              AND env = @env
              AND status != 'revoked'
            ORDER BY last_seen_at DESC NULLS LAST
            """;

        var candidates = new List<RelayCandidate>();
        await using var conn = await _db.OpenConnectionAsync(ct);
        await using var cmd  = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@org_id",  orgId);
        cmd.Parameters.AddWithValue("@site_id", siteId);
        cmd.Parameters.AddWithValue("@env",     env);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            candidates.Add(new RelayCandidate(
                RelayId:    reader.GetGuid(0),
                SiteId:     reader.IsDBNull(1) ? null : reader.GetGuid(1),
                Env:        reader.GetString(2),
                LastSeenAt: reader.IsDBNull(3) ? null : reader.GetFieldValue<DateTimeOffset>(3)));
        }
        return candidates;
    }
}
