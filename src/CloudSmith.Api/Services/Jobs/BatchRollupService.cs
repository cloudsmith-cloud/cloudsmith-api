// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Services.Jobs;

/// <summary>
/// AB#4843 — rolls a child job's terminal transition up into its batch:
/// syncs the read-only item projection, recomputes batch status/counters from
/// child job states, and emits the batch completion notification when the last
/// child reaches a terminal state. Called from every terminal-transition site
/// (job.result arrival, timeout sweep, rejected ack, no-route failure) — there
/// is no batch-side processor.
/// </summary>
public interface IBatchRollupService
{
    /// <summary>
    /// Rolls up the batch containing <paramref name="jobId"/>, if any.
    /// No-op for jobs that are not batch children. Never throws — rollup is
    /// derived state and the next terminal child (or a re-read) reconciles it.
    /// </summary>
    Task OnJobTerminalAsync(Guid jobId, CancellationToken ct = default);
}

/// <inheritdoc cref="IBatchRollupService"/>
public sealed class PostgresBatchRollupService : IBatchRollupService
{
    private readonly NpgsqlDataSource _db;
    private readonly ILogger<PostgresBatchRollupService> _logger;

    public PostgresBatchRollupService(NpgsqlDataSource db, ILogger<PostgresBatchRollupService> logger)
    {
        _db     = db;
        _logger = logger;
    }

    public async Task OnJobTerminalAsync(Guid jobId, CancellationToken ct = default)
    {
        try
        {
            await using var conn = await _db.OpenConnectionAsync(ct);

            // 1. Is this job a batch child?
            Guid batchId;
            await using (var cmd = new NpgsqlCommand(
                "SELECT batch_id FROM core.job_batch_items WHERE job_id = @job_id", conn))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@job_id", NpgsqlDbType.Uuid) { Value = jobId });
                var result = await cmd.ExecuteScalarAsync(ct);
                if (result is not Guid b) return;
                batchId = b;
            }

            // 2. Sync the item's read-only projection of the linked job (Wave 1
            //    keeps item columns synced for portal compatibility).
            await using (var cmd = new NpgsqlCommand("""
                UPDATE core.job_batch_items i
                SET status        = j.status,
                    started_at    = j.started_at,
                    completed_at  = j.completed_at,
                    error_message = j.error_message
                FROM core.jobs j
                WHERE j.job_id = i.job_id AND i.job_id = @job_id
                """, conn))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@job_id", NpgsqlDbType.Uuid) { Value = jobId });
                await cmd.ExecuteNonQueryAsync(ct);
            }

            // 3. Aggregate child job states (pure function — never stored authority).
            var rows = new List<(string Status, int Count)>();
            await using (var cmd = new NpgsqlCommand("""
                SELECT COALESCE(j.status, i.status) AS status, COUNT(*)::int
                FROM core.job_batch_items i
                LEFT JOIN core.jobs j ON j.job_id = i.job_id
                WHERE i.batch_id = @batch_id
                GROUP BY COALESCE(j.status, i.status)
                """, conn))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                    rows.Add((reader.GetString(0), reader.GetInt32(1)));
            }

            var counts = BatchStatusAggregator.FromStatusCounts(rows);
            var status = BatchStatusAggregator.Compute(counts);

            // 4. Write counters + status. The WHERE guard means exactly one caller
            //    wins the flip into a terminal batch status — that caller emits the
            //    completion notification (fires when the LAST child goes terminal).
            var flippedTerminal = false;
            if (BatchStatuses.IsTerminal(status))
            {
                await using var cmd = new NpgsqlCommand("""
                    UPDATE core.job_batches
                    SET status          = @status,
                        completed_items = @completed,
                        failed_items    = @failed,
                        updated_at      = now()
                    WHERE batch_id = @batch_id
                      AND status NOT IN ('succeeded','partial','failed','cancelled')
                    RETURNING batch_id
                    """, conn);
                cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                cmd.Parameters.Add(new NpgsqlParameter("@status", NpgsqlDbType.Text) { Value = status });
                cmd.Parameters.Add(new NpgsqlParameter("@completed", NpgsqlDbType.Integer) { Value = counts.Succeeded });
                cmd.Parameters.Add(new NpgsqlParameter("@failed", NpgsqlDbType.Integer)
                    { Value = counts.Failed + counts.TimedOut + counts.Cancelled });
                flippedTerminal = await cmd.ExecuteScalarAsync(ct) is Guid;
            }
            else
            {
                await using var cmd = new NpgsqlCommand("""
                    UPDATE core.job_batches
                    SET status          = @status,
                        completed_items = @completed,
                        failed_items    = @failed,
                        updated_at      = now()
                    WHERE batch_id = @batch_id
                    """, conn);
                cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                cmd.Parameters.Add(new NpgsqlParameter("@status", NpgsqlDbType.Text) { Value = status });
                cmd.Parameters.Add(new NpgsqlParameter("@completed", NpgsqlDbType.Integer) { Value = counts.Succeeded });
                cmd.Parameters.Add(new NpgsqlParameter("@failed", NpgsqlDbType.Integer)
                    { Value = counts.Failed + counts.TimedOut + counts.Cancelled });
                await cmd.ExecuteNonQueryAsync(ct);
            }

            if (flippedTerminal)
                await EmitBatchNotificationAsync(conn, batchId, status, counts, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Batch rollup for job {JobId} failed — derived state reconciles on the next terminal child", jobId);
        }
    }

    /// <summary>
    /// Emits the job.batch.completed / job.batch.failed notification to the batch
    /// creator — same rows the retired InProcessJobBatchProcessor produced, now
    /// driven by the last child-job terminal transition. Best-effort.
    /// </summary>
    private async Task EmitBatchNotificationAsync(
        NpgsqlConnection conn, Guid batchId, string status, BatchChildCounts counts, CancellationToken ct)
    {
        try
        {
            Guid orgId, createdBy;
            string operation;
            int total;
            await using (var cmd = new NpgsqlCommand("""
                SELECT org_id, created_by, operation, total_items
                FROM core.job_batches WHERE batch_id = @batch_id
                """, conn))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct)) return;
                orgId     = reader.GetGuid(0);
                createdBy = reader.GetGuid(1);
                operation = reader.GetString(2);
                total     = reader.GetInt32(3);
            }

            var succeededOverall = status == BatchStatuses.Succeeded;
            var type  = succeededOverall ? "job.batch.completed" : "job.batch.failed";
            var title = succeededOverall ? $"Batch {operation} completed" : $"Batch {operation} failed";
            var unsuccessful = counts.Failed + counts.TimedOut + counts.Cancelled;
            var message = succeededOverall
                ? $"{counts.Succeeded}/{total} items succeeded."
                : $"{unsuccessful}/{total} items failed.";

            var metadataJson = JsonSerializer.Serialize(new
            {
                batchId = batchId.ToString(),
                operation,
                total,
                completed = counts.Succeeded,
                failed = unsuccessful,
                status,
            });

            await using var notifCmd = new NpgsqlCommand("""
                INSERT INTO core.notifications (user_id, org_id, type, title, message, metadata)
                VALUES (@user_id, @org_id, @type, @title, @message, @metadata::jsonb)
                """, conn);
            notifCmd.Parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = createdBy });
            notifCmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
            notifCmd.Parameters.Add(new NpgsqlParameter("@type", NpgsqlDbType.Text) { Value = type });
            notifCmd.Parameters.Add(new NpgsqlParameter("@title", NpgsqlDbType.Text) { Value = title });
            notifCmd.Parameters.Add(new NpgsqlParameter("@message", NpgsqlDbType.Text) { Value = message });
            notifCmd.Parameters.Add(new NpgsqlParameter("@metadata", NpgsqlDbType.Text) { Value = metadataJson });
            await notifCmd.ExecuteNonQueryAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to emit completion notification for batch {BatchId}", batchId);
        }
    }
}
