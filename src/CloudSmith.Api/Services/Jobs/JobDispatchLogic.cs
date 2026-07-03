// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using CloudSmith.Api.Relay;
using CloudSmith.Core.Jobs;

namespace CloudSmith.Api.Services.Jobs;

/// <summary>A queued core.jobs row claimed by the dispatcher for a dispatch attempt.</summary>
public sealed record QueuedJobClaim(
    Guid    JobId,
    Guid    OrgId,
    string  JobType,
    string  PayloadJson,
    string? IdempotencyKey,
    Guid?   SiteId,
    string  Env);

/// <summary>A non-terminal job past its timeout_at deadline, loaded by the sweeper.</summary>
public sealed record ExpiredJob(Guid JobId, Guid OrgId, string Status);

/// <summary>
/// Pure dispatch/sweep decision logic for the Job Engine dispatcher (AB#4844),
/// separated from the BackgroundService so it is unit-testable against fakes.
/// All state transitions go through <see cref="IJobService.TryTransitionAsync"/>,
/// which enforces the canonical legal-transition table (contract §2, AB#4839)
/// and increments attempt_count on every → dispatched transition.
/// </summary>
public static class JobDispatchLogic
{
    /// <summary>
    /// Dispatches one claimed queued job: builds the canonical job.dispatch frame,
    /// sends it via the relay dispatch service, and on successful send transitions
    /// queued → dispatched. When no relay is connected (or the send fails) the job
    /// is left queued for the next dispatch cycle / timeout sweep (contract §6.1).
    /// </summary>
    public static async Task<DispatchStatus> DispatchOneAsync(
        QueuedJobClaim job,
        IRelayDispatchService dispatch,
        IJobService jobs,
        ILogger logger,
        CancellationToken ct)
    {
        var frame = new JobDispatch(
            JobId:          job.JobId,
            JobType:        job.JobType,
            PayloadJson:    job.PayloadJson,
            IdempotencyKey: job.IdempotencyKey,
            Traceparent:    Activity.Current?.Id);

        var result = await dispatch.TryDispatchAsync(job.OrgId, job.SiteId, job.Env, frame, ct);

        if (result.Status == DispatchStatus.Dispatched)
        {
            // Contract §2: queued → dispatched; attempt_count increments in the core
            // service. A false return means a concurrent actor won the race (e.g. a
            // cancel) — the dispatch itself is harmless (relay-side dedupe, §4.2).
            if (!await jobs.TryTransitionAsync(job.JobId, JobStatuses.Queued, JobStatuses.Dispatched, ct))
            {
                logger.LogInformation(
                    "Job {JobId}: dispatched to relay {RelayId} but queued→dispatched transition lost a race — leaving state alone",
                    job.JobId, result.RelayId);
            }
        }

        return result.Status;
    }

    /// <summary>
    /// Adjudicates one job past its timeout_at deadline (contract: timeout policy —
    /// the API watchdog owns timeouts; relays/agents never fabricate them):
    /// queued → failed with error_code 'no-route' (never routed before deadline),
    /// dispatched/running → timed_out.
    /// </summary>
    public static async Task SweepOneAsync(
        ExpiredJob job,
        IJobService jobs,
        ILogger logger,
        CancellationToken ct)
    {
        switch (job.Status)
        {
            case JobStatuses.Queued:
                if (await jobs.TryTransitionAsync(job.JobId, JobStatuses.Queued, JobStatuses.Failed, ct))
                {
                    await jobs.UpdateJobStatusAsync(job.JobId, job.OrgId, JobStatuses.Failed,
                        errorCode: "no-route",
                        errorMessage: "No matching (site_id, env) relay connected before timeout_at.",
                        ct: ct);
                    logger.LogWarning("Job {JobId}: timed out while queued — failed with no-route", job.JobId);
                }
                break;

            case JobStatuses.Dispatched:
            case JobStatuses.Running:
                if (await jobs.TryTransitionAsync(job.JobId, job.Status, JobStatuses.TimedOut, ct))
                {
                    logger.LogWarning("Job {JobId}: {Status} past timeout_at — timed_out", job.JobId, job.Status);
                }
                break;

            default:
                // Terminal — nothing to do (defensive; the sweep query excludes these).
                break;
        }
    }
}
