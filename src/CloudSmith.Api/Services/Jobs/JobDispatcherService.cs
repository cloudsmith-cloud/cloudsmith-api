// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Relay;
using CloudSmith.Core.Jobs;
using Npgsql;

namespace CloudSmith.Api.Services.Jobs;

/// <summary>Tunables for the Job Engine dispatcher (bound from config section "JobDispatcher").</summary>
public sealed class JobDispatcherOptions
{
    /// <summary>How often the dispatch loop claims queued jobs.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>How often the timeout sweeper runs.</summary>
    public TimeSpan SweepInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Startup-rescan grace: dispatched jobs older than this are requeued
    /// (contract §6.1 — the relay-side duplicate ack makes over-eager requeue harmless).
    /// </summary>
    public TimeSpan RedispatchGrace { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Max queued jobs claimed per dispatch cycle.</summary>
    public int ClaimBatchSize { get; set; } = 20;
}

/// <summary>
/// AB#4844 — durable Job Engine dispatcher. Claims queued core.jobs rows with
/// FOR UPDATE SKIP LOCKED, resolves a connected relay by strict (site_id, env)
/// routing, sends the canonical job.dispatch frame, and transitions
/// queued → dispatched via the core job service. On startup it rescans ALL
/// non-terminal jobs (contract §6.1, AB#2765): stale dispatched jobs are requeued
/// and an immediate timeout sweep adjudicates expired jobs. The periodic timeout
/// sweeper transitions dispatched/running jobs past timeout_at to timed_out and
/// fails queued jobs that were never routable (error_code 'no-route').
/// </summary>
public sealed class JobDispatcherService : BackgroundService
{
    private readonly NpgsqlDataSource _db;
    private readonly IRelayDispatchService _dispatch;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly JobDispatcherOptions _options;
    private readonly ILogger<JobDispatcherService> _logger;

    public JobDispatcherService(
        NpgsqlDataSource db,
        IRelayDispatchService dispatch,
        IServiceScopeFactory scopeFactory,
        JobDispatcherOptions options,
        ILogger<JobDispatcherService> logger)
    {
        _db           = db;
        _dispatch     = dispatch;
        _scopeFactory = scopeFactory;
        _options      = options;
        _logger       = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Contract §6.1 — no job may be stranded in a non-terminal state by an API restart.
        try
        {
            await StartupRescanAsync(stoppingToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Job dispatcher startup rescan failed — continuing; the dispatch loop and sweeper reconcile");
        }

        var nextSweep = DateTimeOffset.UtcNow;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await DispatchQueuedAsync(stoppingToken);

                if (DateTimeOffset.UtcNow >= nextSweep)
                {
                    await SweepTimeoutsAsync(stoppingToken);
                    nextSweep = DateTimeOffset.UtcNow + _options.SweepInterval;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Job dispatcher cycle failed — retrying next interval");
            }

            try
            {
                await Task.Delay(_options.PollInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Startup rescan (contract §6.1): requeue dispatched jobs older than the
    /// redispatch grace (dispatched → queued; relay-side duplicate ack makes
    /// over-eager requeue harmless), then run an immediate timeout sweep so
    /// expired running/dispatched jobs are adjudicated. Queued jobs re-enter the
    /// dispatch loop normally; in-deadline running jobs are left alone.
    /// </summary>
    private async Task StartupRescanAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var jobs = scope.ServiceProvider.GetRequiredService<IJobService>();

        var stale = new List<Guid>();
        await using (var conn = await _db.OpenConnectionAsync(ct))
        {
            // core.jobs has no dispatched_at column in Wave 1; created_at age is the
            // grace proxy. Requeueing an acked job is harmless per contract §4.2/§6.1.
            await using var cmd = new NpgsqlCommand("""
                SELECT job_id
                FROM core.jobs
                WHERE status = 'dispatched'
                  AND created_at < now() - @grace
                """, conn);
            cmd.Parameters.AddWithValue("@grace", _options.RedispatchGrace);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                stale.Add(reader.GetGuid(0));
        }

        foreach (var jobId in stale)
        {
            if (await jobs.TryTransitionAsync(jobId, JobStatuses.Dispatched, JobStatuses.Queued, ct))
                _logger.LogInformation("Startup rescan: job {JobId} requeued (dispatched → queued)", jobId);
        }

        _logger.LogInformation("Startup rescan complete — {Count} dispatched job(s) requeued", stale.Count);

        await SweepTimeoutsAsync(ct);
    }

    /// <summary>
    /// Claims up to ClaimBatchSize queued routable jobs (FOR UPDATE SKIP LOCKED —
    /// two dispatcher replicas never claim the same rows in the same cycle) and
    /// attempts a dispatch for each. Jobs with no eligible relay stay queued.
    /// </summary>
    private async Task DispatchQueuedAsync(CancellationToken ct)
    {
        var claims = new List<QueuedJobClaim>();

        await using (var conn = await _db.OpenConnectionAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT job_id, org_id, job_type, payload_json::text, idempotency_key, site_id, env
                FROM core.jobs
                WHERE status = 'queued'
                  AND site_id IS NOT NULL
                ORDER BY created_at
                LIMIT @batch
                FOR UPDATE SKIP LOCKED
                """, conn, tx);
            cmd.Parameters.AddWithValue("@batch", _options.ClaimBatchSize);

            await using (var reader = await cmd.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    claims.Add(new QueuedJobClaim(
                        JobId:          reader.GetGuid(0),
                        OrgId:          reader.GetGuid(1),
                        JobType:        reader.GetString(2),
                        PayloadJson:    reader.GetString(3),
                        IdempotencyKey: reader.IsDBNull(4) ? null : reader.GetString(4),
                        SiteId:         reader.IsDBNull(5) ? null : reader.GetGuid(5),
                        Env:            reader.GetString(6)));
                }
            }

            // Release row locks before the (potentially slow) WebSocket sends; the
            // CAS in TryTransitionAsync guards the state change, and a double-send
            // races harmlessly into the relay's duplicate dedupe (contract §4.2).
            await tx.CommitAsync(ct);
        }

        if (claims.Count == 0) return;

        using var scope = _scopeFactory.CreateScope();
        var jobs = scope.ServiceProvider.GetRequiredService<IJobService>();

        foreach (var claim in claims)
        {
            ct.ThrowIfCancellationRequested();
            await JobDispatchLogic.DispatchOneAsync(claim, _dispatch, jobs, _logger, ct);
        }
    }

    /// <summary>
    /// Timeout sweep: loads all non-terminal jobs past timeout_at and adjudicates
    /// each per the timeout policy (API-side watchdog owns timeouts).
    /// </summary>
    private async Task SweepTimeoutsAsync(CancellationToken ct)
    {
        var expired = new List<ExpiredJob>();

        await using (var conn = await _db.OpenConnectionAsync(ct))
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT job_id, org_id, status
                FROM core.jobs
                WHERE timeout_at IS NOT NULL
                  AND timeout_at < now()
                  AND status IN ('queued','dispatched','running')
                """, conn);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                expired.Add(new ExpiredJob(reader.GetGuid(0), reader.GetGuid(1), reader.GetString(2)));
        }

        if (expired.Count == 0) return;

        using var scope = _scopeFactory.CreateScope();
        var jobs = scope.ServiceProvider.GetRequiredService<IJobService>();

        foreach (var job in expired)
        {
            ct.ThrowIfCancellationRequested();
            await JobDispatchLogic.SweepOneAsync(job, jobs, _logger, ct);
        }
    }
}
