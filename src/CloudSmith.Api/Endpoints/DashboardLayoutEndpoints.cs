// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

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
/// User dashboard layout persistence endpoints — AB#1930.
/// GET  /api/v1/users/me/dashboard-layout  — returns saved layout (empty array if none).
/// PATCH /api/v1/users/me/dashboard-layout — upserts layout for the calling user.
/// Layout is stored as a jsonb column in core.user_preferences keyed by (user_id, 'dashboard_layout').
/// </summary>
public static class DashboardLayoutEndpoints
{
    private const string PreferenceKey = "dashboard_layout";

    public sealed record DashboardLayoutResponse(IReadOnlyList<JsonElement> Layout);

    public sealed record PatchDashboardLayoutRequest(IReadOnlyList<JsonElement>? Layout);

    public static IEndpointRouteBuilder MapDashboardLayoutEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/users/me").WithTags("Users");

        // GET /api/v1/users/me/dashboard-layout
        group.MapGet("/dashboard-layout", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetUserId(ctx, out var userId, out var error))
                return error!;

            const string sql = """
                SELECT value
                FROM core.user_preferences
                WHERE user_id = @user_id AND key = @key
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = userId });
            cmd.Parameters.Add(new NpgsqlParameter("@key", NpgsqlDbType.Text) { Value = PreferenceKey });

            var scalar = await cmd.ExecuteScalarAsync(ct);
            if (scalar is null || scalar is DBNull)
            {
                return Results.Ok(new { layout = Array.Empty<object>() });
            }

            // value column is jsonb; Npgsql returns it as a string in this path.
            var jsonText = (string)scalar;
            try
            {
                using var doc = JsonDocument.Parse(jsonText);
                var layout = doc.RootElement.ValueKind == JsonValueKind.Array
                    ? doc.RootElement.EnumerateArray().Select(e => e.Clone()).ToArray()
                    : Array.Empty<JsonElement>();
                return Results.Ok(new { layout });
            }
            catch (JsonException)
            {
                return Results.Ok(new { layout = Array.Empty<object>() });
            }
        })
        .RequireAuthorization()
        .WithSummary("Get the calling user's saved dashboard layout. Returns empty array if none saved. AB#1930.");

        // PATCH /api/v1/users/me/dashboard-layout
        group.MapPatch("/dashboard-layout", async (
            PatchDashboardLayoutRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetUserId(ctx, out var userId, out var error))
                return error!;

            var layout = req.Layout ?? Array.Empty<JsonElement>();
            var layoutJson = JsonSerializer.Serialize(layout);

            const string sql = """
                INSERT INTO core.user_preferences (user_id, key, value, updated_at)
                VALUES (@user_id, @key, @value::jsonb, now())
                ON CONFLICT (user_id, key) DO UPDATE
                    SET value = EXCLUDED.value, updated_at = now()
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@user_id", NpgsqlDbType.Uuid) { Value = userId });
            cmd.Parameters.Add(new NpgsqlParameter("@key", NpgsqlDbType.Text) { Value = PreferenceKey });
            cmd.Parameters.Add(new NpgsqlParameter("@value", NpgsqlDbType.Text) { Value = layoutJson });

            await cmd.ExecuteNonQueryAsync(ct);

            return Results.Ok(new { layout });
        })
        .RequireAuthorization()
        .WithSummary("Upsert the calling user's dashboard layout. AB#1930.");

        return app;
    }

    private static bool TryGetUserId(HttpContext ctx, out Guid userId, out IResult? error)
    {
        userId = Guid.Empty;
        // Prefer the OrgContext middleware's resolved UserId; fall back to JWT sub.
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
