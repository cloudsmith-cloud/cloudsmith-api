// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Npgsql;

namespace CloudSmith.Api.Services.Jobs;

/// <summary>
/// Minimal jobId → org lookup for handlers that operate on the system-context
/// Relay hop (job.ack / job.result), where frames are keyed by jobId only but
/// downstream writes (error fields, audit rows) need the owning org.
/// </summary>
public interface IJobDirectory
{
    /// <summary>Returns the org_id of the job, or null when the job does not exist.</summary>
    Task<Guid?> GetOrgIdAsync(Guid jobId, CancellationToken ct = default);
}

/// <inheritdoc cref="IJobDirectory"/>
public sealed class PostgresJobDirectory : IJobDirectory
{
    private readonly NpgsqlDataSource _db;

    public PostgresJobDirectory(NpgsqlDataSource db) => _db = db;

    public async Task<Guid?> GetOrgIdAsync(Guid jobId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenConnectionAsync(ct);
        await using var cmd  = new NpgsqlCommand(
            "SELECT org_id FROM core.jobs WHERE job_id = @job_id", conn);
        cmd.Parameters.AddWithValue("@job_id", jobId);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is Guid orgId ? orgId : null;
    }
}
