// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Services;

/// <summary>
/// Lightweight notification writer — AB#1932.
/// Called by job completion/failure paths to create user-visible notification records.
/// Also used by any other platform event that should surface in the notification feed.
/// </summary>
public interface INotificationService
{
    /// <summary>
    /// Creates a notification for the specified user.
    /// Best-effort — never throws; failures are logged at Warning.
    /// </summary>
    Task CreateAsync(
        Guid orgId,
        Guid userId,
        string type,
        string title,
        string message,
        string? metadataJson = null,
        CancellationToken ct = default);
}

/// <summary>
/// Writes directly to core.notifications via Npgsql.
/// </summary>
public sealed class PostgresNotificationService : INotificationService
{
    private readonly NpgsqlDataSource _db;
    private readonly ILogger<PostgresNotificationService> _logger;

    public PostgresNotificationService(
        NpgsqlDataSource db,
        ILogger<PostgresNotificationService> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task CreateAsync(
        Guid orgId,
        Guid userId,
        string type,
        string title,
        string message,
        string? metadataJson = null,
        CancellationToken ct = default)
    {
        try
        {
            await using var conn = await _db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO core.notifications
                    (user_id, org_id, type, title, message, metadata)
                VALUES
                    (@user_id, @org_id, @type, @title, @message, @metadata::jsonb)
                """, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = userId });
            cmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
            cmd.Parameters.Add(new NpgsqlParameter("@type", NpgsqlDbType.Text) { Value = type });
            cmd.Parameters.Add(new NpgsqlParameter("@title", NpgsqlDbType.Text) { Value = title });
            cmd.Parameters.Add(new NpgsqlParameter("@message", NpgsqlDbType.Text) { Value = message });
            cmd.Parameters.Add(new NpgsqlParameter("@metadata", NpgsqlDbType.Text)
                { Value = metadataJson is null ? DBNull.Value : (object)metadataJson });
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to create notification for user {UserId} org {OrgId} type {Type}",
                userId, orgId, type);
        }
    }
}
