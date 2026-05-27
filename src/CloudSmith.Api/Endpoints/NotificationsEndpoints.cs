// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using CloudSmith.Api.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Notifications endpoints — AB#1932.
/// GET    /api/v1/notifications?limit=50          — list newest-first notifications for the calling user.
/// PATCH  /api/v1/notifications/{id}/read         — mark a single notification read.
/// POST   /api/v1/notifications/read-all          — mark all notifications read for the calling user.
/// Notifications are stored in core.notifications.
/// </summary>
public static class NotificationsEndpoints
{
    private const int DefaultLimit = 50;
    private const int MaxLimit = 200;

    public sealed record NotificationResponse(
        string Id,
        string Type,
        string Title,
        string Message,
        bool Read,
        string CreatedAt,
        object? Metadata);

    public static IEndpointRouteBuilder MapNotificationsEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/notifications").WithTags("Notifications");

        // GET /api/v1/notifications?limit=50
        group.MapGet("/", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            int? limit,
            CancellationToken ct) =>
        {
            if (!TryGetUserId(ctx, out var userId, out var error))
                return error!;

            var resolvedLimit = limit is null or < 1 ? DefaultLimit : Math.Min(limit.Value, MaxLimit);

            const string sql = """
                SELECT notification_id, type, title, message, read, created_at, metadata
                FROM core.notifications
                WHERE user_id = @user_id
                ORDER BY created_at DESC, notification_id DESC
                LIMIT @limit
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = userId });
            cmd.Parameters.Add(new NpgsqlParameter("@limit", NpgsqlDbType.Integer) { Value = resolvedLimit });

            var items = new List<NotificationResponse>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                items.Add(ReadNotification(reader));
            }

            return Results.Ok(new { items });
        })
        .RequireAuthorization()
        .WithSummary("List notifications for the calling user, newest-first. AB#1932.");

        // PATCH /api/v1/notifications/{id}/read
        group.MapPatch("/{id:guid}/read", async (
            Guid id,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetUserId(ctx, out var userId, out var error))
                return error!;

            const string sql = """
                UPDATE core.notifications
                SET read = true
                WHERE notification_id = @id AND user_id = @user_id
                RETURNING notification_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@id", NpgsqlDbType.Uuid) { Value = id });
            cmd.Parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = userId });

            var result = await cmd.ExecuteScalarAsync(ct);
            if (result is null || result is DBNull)
                return Results.NotFound(new { error = "notification-not-found" });

            return Results.NoContent();
        })
        .RequireAuthorization()
        .WithSummary("Mark a notification as read for the calling user. AB#1932.");

        // POST /api/v1/notifications/read-all
        group.MapPost("/read-all", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetUserId(ctx, out var userId, out var error))
                return error!;

            const string sql = """
                UPDATE core.notifications
                SET read = true
                WHERE user_id = @user_id AND read = false
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = userId });
            var affected = await cmd.ExecuteNonQueryAsync(ct);

            return Results.Ok(new { marked = affected });
        })
        .RequireAuthorization()
        .WithSummary("Mark all unread notifications read for the calling user. AB#1932.");

        return app;
    }

    private static NotificationResponse ReadNotification(NpgsqlDataReader reader)
    {
        var id = reader.GetGuid(0).ToString();
        var type = reader.GetString(1);
        var title = reader.GetString(2);
        var message = reader.GetString(3);
        var read = reader.GetBoolean(4);
        var createdAt = reader.GetDateTime(5).ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
        object? metadata = null;
        if (!reader.IsDBNull(6))
        {
            try
            {
                using var doc = JsonDocument.Parse(reader.GetString(6));
                metadata = doc.RootElement.Clone();
            }
            catch (JsonException) { /* leave null */ }
        }
        return new NotificationResponse(id, type, title, message, read, createdAt, metadata);
    }

    private static bool TryGetUserId(HttpContext ctx, out Guid userId, out IResult? error)
    {
        userId = Guid.Empty;
        if (ctx.Items["UserId"] is Guid id)
        {
            userId = id;
            error = null;
            return true;
        }
        var subClaim = ctx.User.FindFirstValue("sub")
            ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrEmpty(subClaim) && Guid.TryParse(subClaim, out userId))
        {
            error = null;
            return true;
        }
        error = Results.Json(
            new { error = "missing-user-context", message = "The caller's user id could not be resolved." },
            statusCode: StatusCodes.Status400BadRequest);
        return false;
    }
}
