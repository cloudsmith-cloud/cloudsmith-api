// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using System.Text.Json;
using CloudSmith.Core.Jobs;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Services.Jobs;

/// <summary>
/// Writes the core.audit_log row for a job that reached a terminal state via a
/// relay-forwarded job.result frame (AB#4841). Actor is the system/relay context
/// (user_id NULL), action is <c>job.completed</c>, and the correlation id derives
/// from the ambient W3C trace context (traceparent trace-id).
/// </summary>
public interface IJobAuditWriter
{
    Task WriteJobCompletedAsync(Guid orgId, Guid jobId, Guid relayId, JobResult result, CancellationToken ct = default);
}

/// <inheritdoc cref="IJobAuditWriter"/>
public sealed class PostgresJobAuditWriter : IJobAuditWriter
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly NpgsqlDataSource _db;
    private readonly ILogger<PostgresJobAuditWriter> _logger;

    public PostgresJobAuditWriter(NpgsqlDataSource db, ILogger<PostgresJobAuditWriter> logger)
    {
        _db     = db;
        _logger = logger;
    }

    public async Task WriteJobCompletedAsync(Guid orgId, Guid jobId, Guid relayId, JobResult result, CancellationToken ct = default)
    {
        var afterJson = JsonSerializer.Serialize(new
        {
            actor       = "system/relay",
            relayId     = relayId.ToString(),
            succeeded   = result.Succeeded,
            exitCode    = result.ExitCode,
            error       = result.Error,
            completedAt = result.CompletedAt,
        }, JsonOpts);

        try
        {
            await using var conn = await _db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO core.audit_log
                    (org_id, user_id, action, resource_type, resource_id, after_json, correlation_id)
                VALUES
                    (@org_id, NULL, 'job.completed', 'job', @resource_id, @after_json::jsonb, @correlation_id)
                """, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
            cmd.Parameters.Add(new NpgsqlParameter("@resource_id", NpgsqlDbType.Uuid) { Value = jobId });
            cmd.Parameters.Add(new NpgsqlParameter("@after_json", NpgsqlDbType.Text) { Value = afterJson });
            cmd.Parameters.Add(new NpgsqlParameter("@correlation_id", NpgsqlDbType.Uuid)
                { Value = (object?)CorrelationFromTraceContext() ?? DBNull.Value });
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (Exception ex)
        {
            // Audit is best-effort on this hop — the job result itself is already
            // durably persisted; never fail the frame handler over an audit write.
            _logger.LogError(ex, "Failed to write job.completed audit row for job {JobId}", jobId);
        }
    }

    /// <summary>
    /// Derives a Guid correlation id from the ambient W3C traceparent trace-id
    /// (16 bytes → Guid). Returns null when no activity/trace context is present.
    /// </summary>
    internal static Guid? CorrelationFromTraceContext()
    {
        var traceId = Activity.Current?.TraceId;
        if (traceId is null || traceId.Value == default)
            return null;
        return Guid.ParseExact(traceId.Value.ToString(), "N");
    }
}
