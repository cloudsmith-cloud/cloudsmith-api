// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Security.Claims;
using System.Text;
using CloudSmith.Api.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Audit log query endpoint — AB#1651.
/// GET /api/v1/audit — paged, filterable query over <c>core.audit_log</c>.
/// Scoped to the caller's org via the <c>org_id</c> claim; requires <c>audit:read</c> permission.
/// </summary>
public static class AuditEndpoints
{
    private const int DefaultPageSize = 50;
    private const int MaxPageSize = 200;

    public sealed record AuditEntryResponse(
        long AuditId,
        Guid? UserId,
        string Action,
        string ResourceType,
        Guid? ResourceId,
        Guid? CorrelationId,
        string? IpAddress,
        string? UserAgent,
        string OccurredAt);

    public sealed record AuditQueryResponse(
        IReadOnlyList<AuditEntryResponse> Items,
        long TotalCount,
        int Page,
        int PageSize);

    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/audit").WithTags("Audit");

        // GET /api/v1/audit?actor=<userId>&action=<action>&resourceType=<type>&from=<iso>&to=<iso>&page=1&pageSize=50
        // Returns { items: [...], totalCount, page, pageSize } — DESC by occurred_at.
        group.MapGet("/", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            string? actor,
            string? action,
            string? resourceType,
            string? from,
            string? to,
            int? page,
            int? pageSize,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var resolvedPage = page is null or < 1 ? 1 : page.Value;
            var resolvedPageSize = pageSize is null or < 1 ? DefaultPageSize : Math.Min(pageSize.Value, MaxPageSize);

            // Optional filters — parse early so a bad input returns 400 instead of a SQL error.
            Guid? actorUserId = null;
            if (!string.IsNullOrWhiteSpace(actor))
            {
                if (!Guid.TryParse(actor, out var parsedActor))
                {
                    return Results.Json(new { error = "invalid-actor", message = "actor must be a user UUID." }, statusCode: StatusCodes.Status400BadRequest);
                }
                actorUserId = parsedActor;
            }

            DateTime? fromUtc = null;
            if (!string.IsNullOrWhiteSpace(from))
            {
                if (!TryParseIsoUtc(from, out var parsedFrom))
                {
                    return Results.Json(new { error = "invalid-from", message = "from must be an ISO-8601 timestamp." }, statusCode: StatusCodes.Status400BadRequest);
                }
                fromUtc = parsedFrom;
            }

            DateTime? toUtc = null;
            if (!string.IsNullOrWhiteSpace(to))
            {
                if (!TryParseIsoUtc(to, out var parsedTo))
                {
                    return Results.Json(new { error = "invalid-to", message = "to must be an ISO-8601 timestamp." }, statusCode: StatusCodes.Status400BadRequest);
                }
                toUtc = parsedTo;
            }

            // Build a parameterised WHERE clause shared by COUNT(*) and the page query.
            var where = new StringBuilder("WHERE org_id = @org_id");
            var parameters = new List<NpgsqlParameter>
            {
                new("@org_id", NpgsqlDbType.Uuid) { Value = orgId },
            };

            if (actorUserId is not null)
            {
                where.Append(" AND user_id = @user_id");
                parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = actorUserId.Value });
            }

            if (!string.IsNullOrWhiteSpace(action))
            {
                where.Append(" AND action = @action");
                parameters.Add(new NpgsqlParameter("@action", NpgsqlDbType.Text) { Value = action });
            }

            if (!string.IsNullOrWhiteSpace(resourceType))
            {
                where.Append(" AND resource_type = @resource_type");
                parameters.Add(new NpgsqlParameter("@resource_type", NpgsqlDbType.Text) { Value = resourceType });
            }

            if (fromUtc is not null)
            {
                where.Append(" AND occurred_at >= @from_utc");
                parameters.Add(new NpgsqlParameter("@from_utc", NpgsqlDbType.TimestampTz) { Value = fromUtc.Value });
            }

            if (toUtc is not null)
            {
                where.Append(" AND occurred_at <= @to_utc");
                parameters.Add(new NpgsqlParameter("@to_utc", NpgsqlDbType.TimestampTz) { Value = toUtc.Value });
            }

            await using var conn = await db.OpenConnectionAsync(ct);

            // Total count for paging UI.
            long totalCount;
            await using (var countCmd = new NpgsqlCommand($"SELECT COUNT(*) FROM core.audit_log {where}", conn))
            {
                foreach (var p in parameters)
                {
                    countCmd.Parameters.Add(Clone(p));
                }
                var scalar = await countCmd.ExecuteScalarAsync(ct);
                totalCount = scalar is long l ? l : Convert.ToInt64(scalar, CultureInfo.InvariantCulture);
            }

            var offset = (resolvedPage - 1) * resolvedPageSize;
            var pageSql = $"""
                SELECT audit_id, user_id, action, resource_type, resource_id, correlation_id, ip_address, user_agent, occurred_at
                FROM core.audit_log
                {where}
                ORDER BY occurred_at DESC, audit_id DESC
                LIMIT @limit OFFSET @offset
                """;

            var items = new List<AuditEntryResponse>();
            await using (var pageCmd = new NpgsqlCommand(pageSql, conn))
            {
                foreach (var p in parameters)
                {
                    pageCmd.Parameters.Add(Clone(p));
                }
                pageCmd.Parameters.Add(new NpgsqlParameter("@limit", NpgsqlDbType.Integer) { Value = resolvedPageSize });
                pageCmd.Parameters.Add(new NpgsqlParameter("@offset", NpgsqlDbType.Integer) { Value = offset });

                await using var reader = await pageCmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    items.Add(new AuditEntryResponse(
                        AuditId: reader.GetInt64(0),
                        UserId: reader.IsDBNull(1) ? null : reader.GetGuid(1),
                        Action: reader.GetString(2),
                        ResourceType: reader.GetString(3),
                        ResourceId: reader.IsDBNull(4) ? null : reader.GetGuid(4),
                        CorrelationId: reader.IsDBNull(5) ? null : reader.GetGuid(5),
                        IpAddress: reader.IsDBNull(6) ? null : reader.GetString(6),
                        UserAgent: reader.IsDBNull(7) ? null : reader.GetString(7),
                        OccurredAt: reader.GetDateTime(8).ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)));
                }
            }

            return Results.Ok(new AuditQueryResponse(items, totalCount, resolvedPage, resolvedPageSize));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("audit:read")))
        .WithSummary("Query the org audit log with filters + paging (AB#1651).");

        return app;
    }

    private static bool TryParseIsoUtc(string input, out DateTime utc)
    {
        if (DateTime.TryParse(
                input,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
                out var parsed))
        {
            utc = DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
            return true;
        }
        utc = default;
        return false;
    }

    // NpgsqlParameter instances are command-bound — clone so the same logical filter
    // can be re-used across the COUNT and page queries.
    private static NpgsqlParameter Clone(NpgsqlParameter source) =>
        new(source.ParameterName, source.NpgsqlDbType) { Value = source.Value };
}
