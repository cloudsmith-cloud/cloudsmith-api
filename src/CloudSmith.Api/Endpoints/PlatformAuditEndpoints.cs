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
/// Platform audit event ingest endpoint — AB#1929.
/// POST /api/v1/platform/audit — writes a portal-originated event to core.audit_log.
/// Returns 202 Accepted (fire-and-forget from portal perspective).
/// Requires authentication.
/// </summary>
public static class PlatformAuditEndpoints
{
    public sealed record PlatformAuditEventRequest(
        string Event,
        string? From,
        string? To,
        string? UserId,
        string? Timestamp);

    public static IEndpointRouteBuilder MapPlatformAuditEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/platform").WithTags("Platform");

        // POST /api/v1/platform/audit
        // Accepts a portal-originated audit event and appends it to core.audit_log.
        // The portal sends this fire-and-forget; we return 202 immediately regardless of DB outcome.
        group.MapPost("/audit", async (
            PlatformAuditEventRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            if (string.IsNullOrWhiteSpace(req.Event))
            {
                return Results.Json(
                    new { error = "invalid-event", message = "event field is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            // Resolve user_id: prefer the request body's userId (portal may know more),
            // fall back to the JWT sub claim.
            Guid? userId = null;
            if (!string.IsNullOrWhiteSpace(req.UserId) && Guid.TryParse(req.UserId, out var parsedUserId))
            {
                userId = parsedUserId;
            }
            else
            {
                var subClaim = ctx.User.FindFirstValue("sub")
                    ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (!string.IsNullOrEmpty(subClaim) && Guid.TryParse(subClaim, out var subGuid))
                    userId = subGuid;
            }

            // Resolve occurred_at: prefer request timestamp; fall back to server UTC now.
            DateTime occurredAt = DateTime.UtcNow;
            if (!string.IsNullOrWhiteSpace(req.Timestamp)
                && DateTime.TryParse(req.Timestamp, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsedTs))
            {
                occurredAt = DateTime.SpecifyKind(parsedTs, DateTimeKind.Utc);
            }

            // Build after_json with the from/to navigation context the portal provides.
            var afterJson = JsonSerializer.Serialize(new
            {
                @from = req.From,
                to = req.To,
                source = "portal",
            });

            // Persist best-effort — if the DB write fails we still return 202.
            _ = Task.Run(async () =>
            {
                try
                {
                    await using var conn = await db.OpenConnectionAsync(CancellationToken.None);
                    await using var cmd = new NpgsqlCommand("""
                        INSERT INTO core.audit_log
                            (org_id, user_id, action, resource_type, after_json, occurred_at)
                        VALUES
                            (@org_id, @user_id, @action, 'portal-event', @after_json::jsonb, @occurred_at)
                        """, conn);
                    cmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
                    cmd.Parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = userId.HasValue ? userId.Value : DBNull.Value });
                    cmd.Parameters.Add(new NpgsqlParameter("@action", NpgsqlDbType.Text) { Value = req.Event });
                    cmd.Parameters.Add(new NpgsqlParameter("@after_json", NpgsqlDbType.Text) { Value = afterJson });
                    cmd.Parameters.Add(new NpgsqlParameter("@occurred_at", NpgsqlDbType.TimestampTz) { Value = occurredAt });
                    await cmd.ExecuteNonQueryAsync(CancellationToken.None);
                }
                catch
                {
                    // Fire-and-forget — swallow DB errors so the portal is never blocked.
                }
            }, CancellationToken.None);

            return Results.Accepted();
        })
        .RequireAuthorization()
        .WithSummary("Ingest a portal-originated audit event into core.audit_log (fire-and-forget, 202 always). AB#1929.");

        return app;
    }
}
