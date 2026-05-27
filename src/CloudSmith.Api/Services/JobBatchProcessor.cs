// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Services;

/// <summary>
/// In-process sequential batch processor — AB#1931.
/// Phase IV implementation: picks up a batch by ID and processes each sub-task in sequence,
/// updating status columns in core.job_batches and core.job_batch_items.
///
/// Phase V replacement: replace with a durable background worker that pulls from the queue
/// and dispatches sub-tasks to relay agents.
/// </summary>
public interface IJobBatchProcessor
{
    /// <summary>
    /// Enqueues a batch for processing. Returns immediately; processing runs in the background.
    /// </summary>
    Task ProcessBatchAsync(Guid batchId, CancellationToken ct);
}

/// <summary>
/// Sequential in-process implementation.
/// Each resourceId is "processed" by marking it succeeded after a trivial dispatch step.
/// Real operation logic belongs in Phase V module workers.
/// </summary>
public sealed class InProcessJobBatchProcessor : IJobBatchProcessor
{
    private readonly NpgsqlDataSource _db;
    private readonly ILogger<InProcessJobBatchProcessor> _logger;

    public InProcessJobBatchProcessor(NpgsqlDataSource db, ILogger<InProcessJobBatchProcessor> logger)
    {
        _db = db;
        _logger = logger;
    }

    public Task ProcessBatchAsync(Guid batchId, CancellationToken ct)
    {
        // Fire off the actual work on the thread pool — the caller gets 202 immediately.
        _ = Task.Run(() => RunBatchAsync(batchId), ct);
        return Task.CompletedTask;
    }

    private async Task RunBatchAsync(Guid batchId)
    {
        try
        {
            await MarkBatchRunningAsync(batchId);

            // Load all queued items for this batch.
            var items = await LoadItemsAsync(batchId);

            foreach (var itemId in items)
            {
                await ProcessItemAsync(batchId, itemId);
            }

            await MarkBatchDoneAsync(batchId);
            await EmitBatchNotificationAsync(batchId, succeeded: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled error processing batch {BatchId}", batchId);
            await MarkBatchFailedAsync(batchId, ex.Message);
            await EmitBatchNotificationAsync(batchId, succeeded: false);
        }
    }

    private async Task MarkBatchRunningAsync(Guid batchId)
    {
        await using var conn = await _db.OpenConnectionAsync(CancellationToken.None);
        await using var cmd = new NpgsqlCommand("""
            UPDATE core.job_batches
            SET status = 'running', updated_at = now()
            WHERE batch_id = @batch_id
            """, conn);
        cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
        await cmd.ExecuteNonQueryAsync(CancellationToken.None);
    }

    private async Task<IReadOnlyList<Guid>> LoadItemsAsync(Guid batchId)
    {
        var items = new List<Guid>();
        await using var conn = await _db.OpenConnectionAsync(CancellationToken.None);
        await using var cmd = new NpgsqlCommand("""
            SELECT item_id FROM core.job_batch_items
            WHERE batch_id = @batch_id AND status = 'queued'
            ORDER BY item_id
            """, conn);
        cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
        await using var reader = await cmd.ExecuteReaderAsync(CancellationToken.None);
        while (await reader.ReadAsync(CancellationToken.None))
            items.Add(reader.GetGuid(0));
        return items;
    }

    private async Task ProcessItemAsync(Guid batchId, Guid itemId)
    {
        // Mark item running.
        await using var conn = await _db.OpenConnectionAsync(CancellationToken.None);
        await using (var startCmd = new NpgsqlCommand("""
            UPDATE core.job_batch_items
            SET status = 'running', started_at = now()
            WHERE item_id = @item_id
            """, conn))
        {
            startCmd.Parameters.Add(new NpgsqlParameter("@item_id", NpgsqlDbType.Uuid) { Value = itemId });
            await startCmd.ExecuteNonQueryAsync(CancellationToken.None);
        }

        // Phase IV: no actual dispatch logic — mark succeeded immediately.
        // Phase V: dispatch to relay agent, await result, handle failure.
        await using (var doneCmd = new NpgsqlCommand("""
            UPDATE core.job_batch_items
            SET status = 'succeeded', completed_at = now()
            WHERE item_id = @item_id
            """, conn))
        {
            doneCmd.Parameters.Add(new NpgsqlParameter("@item_id", NpgsqlDbType.Uuid) { Value = itemId });
            await doneCmd.ExecuteNonQueryAsync(CancellationToken.None);
        }

        // Increment batch completed count.
        await using (var countCmd = new NpgsqlCommand("""
            UPDATE core.job_batches
            SET completed_items = completed_items + 1, updated_at = now()
            WHERE batch_id = @batch_id
            """, conn))
        {
            countCmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
            await countCmd.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }

    private async Task MarkBatchDoneAsync(Guid batchId)
    {
        await using var conn = await _db.OpenConnectionAsync(CancellationToken.None);
        await using var cmd = new NpgsqlCommand("""
            UPDATE core.job_batches
            SET status = CASE WHEN failed_items = 0 THEN 'succeeded' ELSE 'partial' END,
                updated_at = now()
            WHERE batch_id = @batch_id
            """, conn);
        cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
        await cmd.ExecuteNonQueryAsync(CancellationToken.None);
    }

    private async Task MarkBatchFailedAsync(Guid batchId, string message)
    {
        try
        {
            await using var conn = await _db.OpenConnectionAsync(CancellationToken.None);
            await using var cmd = new NpgsqlCommand("""
                UPDATE core.job_batches
                SET status = 'failed', updated_at = now()
                WHERE batch_id = @batch_id
                """, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
            await cmd.ExecuteNonQueryAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to mark batch {BatchId} as failed", batchId);
        }
    }

    /// <summary>
    /// Emits a notification to the batch creator when the batch completes or fails.
    /// Reads org_id + created_by + operation + status from the DB to build the notification row.
    /// Best-effort — swallows errors so a notification failure never breaks the batch processor.
    /// </summary>
    private async Task EmitBatchNotificationAsync(Guid batchId, bool succeeded)
    {
        try
        {
            await using var conn = await _db.OpenConnectionAsync(CancellationToken.None);

            // Load batch metadata.
            Guid orgId, createdBy;
            string operation;
            int total, completed, failed;
            await using (var cmd = new NpgsqlCommand("""
                SELECT org_id, created_by, operation, total_items, completed_items, failed_items
                FROM core.job_batches WHERE batch_id = @batch_id
                """, conn))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                await using var reader = await cmd.ExecuteReaderAsync(CancellationToken.None);
                if (!await reader.ReadAsync(CancellationToken.None)) return;
                orgId     = reader.GetGuid(0);
                createdBy = reader.GetGuid(1);
                operation = reader.GetString(2);
                total     = reader.GetInt32(3);
                completed = reader.GetInt32(4);
                failed    = reader.GetInt32(5);
            }

            var type  = succeeded ? "job.batch.completed" : "job.batch.failed";
            var title = succeeded
                ? $"Batch {operation} completed"
                : $"Batch {operation} failed";
            var message = succeeded
                ? $"{completed}/{total} items succeeded."
                : $"{failed}/{total} items failed.";

            var metadataJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                batchId = batchId.ToString(),
                operation,
                total,
                completed,
                failed,
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
            await notifCmd.ExecuteNonQueryAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to emit completion notification for batch {BatchId}", batchId);
        }
    }
}
