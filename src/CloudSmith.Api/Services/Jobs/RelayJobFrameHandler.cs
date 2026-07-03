// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Core.Jobs;

namespace CloudSmith.Api.Services.Jobs;

/// <summary>
/// Handles inbound job frames on the PaaS↔Relay WebSocket (contract §1, AB#4839).
/// job.ack (AB#4844): persists dispatch confirmation — replaces the log-only MVP path.
/// Scoped — resolved per relay connection request.
/// </summary>
public sealed class RelayJobFrameHandler
{
    private readonly IJobService _jobs;
    private readonly IJobDirectory _directory;
    private readonly ILogger<RelayJobFrameHandler> _logger;

    public RelayJobFrameHandler(
        IJobService jobs,
        IJobDirectory directory,
        ILogger<RelayJobFrameHandler> logger)
    {
        _jobs      = jobs;
        _directory = directory;
        _logger    = logger;
    }

    /// <summary>
    /// job.ack semantics (contract §1.2 + failure/requeue policy):
    /// <list type="bullet">
    /// <item><c>accepted</c> — the relay durably persisted the job. The dispatcher
    /// already transitioned queued → dispatched on send; a defensive CAS covers the
    /// crash-between-send-and-transition window. Duplicate transitions are no-ops.</item>
    /// <item><c>duplicate</c> — safe re-dispatch of a job already in the relay queue;
    /// state is left alone.</item>
    /// <item><c>rejected</c> — pre-execution failure: the job fails immediately, no
    /// retry, with the relay's detail as error_message.</item>
    /// </list>
    /// </summary>
    public async Task HandleAckAsync(JobAck ack, Guid relayId, CancellationToken ct)
    {
        switch (ack.AckStatus)
        {
            case JobAckStatus.Accepted:
                // Normal path: already dispatched (transition happened on send) — the
                // CAS returns false and nothing changes. If the API crashed between
                // send and transition, this completes the queued → dispatched move.
                if (await _jobs.TryTransitionAsync(ack.JobId, JobStatuses.Queued, JobStatuses.Dispatched, ct))
                {
                    _logger.LogInformation(
                        "Relay {RelayId}: job.ack accepted for {JobId} — completed queued→dispatched (send-side transition was lost)",
                        relayId, ack.JobId);
                }
                else
                {
                    _logger.LogInformation(
                        "Relay {RelayId}: job.ack accepted for {JobId} — dispatch confirmed",
                        relayId, ack.JobId);
                }
                break;

            case JobAckStatus.Duplicate:
                // Contract §4.2 — harmless re-dispatch; leave state alone.
                _logger.LogInformation(
                    "Relay {RelayId}: job.ack duplicate for {JobId} — job already queued relay-side; state unchanged",
                    relayId, ack.JobId);
                break;

            case JobAckStatus.Rejected:
                await HandleRejectedAsync(ack, relayId, ct);
                break;

            default:
                _logger.LogWarning(
                    "Relay {RelayId}: job.ack for {JobId} carried unknown ackStatus {Status} — ignoring",
                    relayId, ack.JobId, ack.AckStatus);
                break;
        }
    }

    private async Task HandleRejectedAsync(JobAck ack, Guid relayId, CancellationToken ct)
    {
        // Failure policy: ackStatus=rejected → failed immediately, no retry.
        // The job is normally 'dispatched' (transitioned on send); 'queued' covers
        // the send/transition race. Both are legal pre-execution failure edges (§2 ¹).
        var transitioned =
            await _jobs.TryTransitionAsync(ack.JobId, JobStatuses.Dispatched, JobStatuses.Failed, ct)
            || await _jobs.TryTransitionAsync(ack.JobId, JobStatuses.Queued, JobStatuses.Failed, ct);

        if (!transitioned)
        {
            _logger.LogWarning(
                "Relay {RelayId}: job.ack rejected for {JobId} but the job is not in a failable state — ignoring",
                relayId, ack.JobId);
            return;
        }

        var orgId = await _directory.GetOrgIdAsync(ack.JobId, ct);
        if (orgId is not null)
        {
            await _jobs.UpdateJobStatusAsync(ack.JobId, orgId.Value, JobStatuses.Failed,
                errorCode: "dispatch-rejected",
                errorMessage: ack.Detail ?? "Relay rejected the dispatch.",
                ct: ct);
        }

        _logger.LogWarning(
            "Relay {RelayId}: job.ack rejected for {JobId} — failed (detail: {Detail})",
            relayId, ack.JobId, ack.Detail ?? "<none>");
    }
}
