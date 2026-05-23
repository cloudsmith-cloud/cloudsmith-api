// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using System.Security.Cryptography;
using CloudSmith.Api.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// User management endpoints — list users + invite new members for an organisation.
/// AB#1648: GET  /api/v1/identity/users         — list active + invited users for the caller's org.
/// AB#1649: POST /api/v1/identity/users/invite  — invite a new user by email with a set of roles.
/// </summary>
public static class UsersEndpoints
{
    private static readonly TimeSpan InvitationLifetime = TimeSpan.FromDays(7);

    public sealed record UserListEntry(
        string UserId,
        string Email,
        string? Username,
        string DisplayName,
        string Status,
        IReadOnlyList<string> Roles,
        string? LastLogin);

    public sealed record InviteUserRequest(
        string Email,
        IReadOnlyList<string>? Roles);

    public sealed record InviteUserResponse(
        string InvitationId,
        string Token,
        string ExpiresAt);

    public static IEndpointRouteBuilder MapUsersEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/identity").WithTags("Identity");

        // GET /api/v1/identity/users — active + invited users for the current org. (AB#1648)
        group.MapGet("/users", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var error))
                return error!;

            // UNION pulls active/deactivated users from core.users and pending/expired/revoked
            // invitations from core.user_invitations. Roles are aggregated from
            // core.role_assignments + core.role_definitions for real users; invitation
            // roles come directly from the invitation row's jsonb roles[] array.
            const string sql = """
                SELECT
                    u.user_id::text                    AS id,
                    u.email                            AS email,
                    u.external_id                      AS username,
                    u.display_name                     AS display_name,
                    CASE WHEN u.is_active THEN 'Active' ELSE 'Deactivated' END AS status,
                    COALESCE(
                        (SELECT jsonb_agg(rd.name ORDER BY rd.name)
                         FROM core.role_assignments ra
                         JOIN core.role_definitions rd ON rd.role_id = ra.role_id
                         WHERE ra.user_id = u.user_id
                           AND ra.org_id  = u.org_id),
                        '[]'::jsonb)                   AS roles,
                    u.last_login_at                    AS last_login,
                    u.created_at                       AS sort_key
                FROM core.users u
                WHERE u.org_id = @org_id

                UNION ALL

                SELECT
                    i.invitation_id::text              AS id,
                    i.email                            AS email,
                    NULL                               AS username,
                    i.email                            AS display_name,
                    'Invited'                          AS status,
                    i.roles                            AS roles,
                    NULL::timestamptz                  AS last_login,
                    i.created_at                       AS sort_key
                FROM core.user_invitations i
                WHERE i.org_id = @org_id
                  AND i.status = 'pending'

                ORDER BY sort_key DESC, email
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var results = new List<UserListEntry>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var id = reader.GetString(0);
                var email = reader.GetString(1);
                var username = reader.IsDBNull(2) ? null : reader.GetString(2);
                var displayName = reader.GetString(3);
                var status = reader.GetString(4);
                var rolesJson = reader.IsDBNull(5) ? "[]" : reader.GetString(5);
                var lastLogin = reader.IsDBNull(6)
                    ? null
                    : reader.GetDateTime(6).ToString("o");

                IReadOnlyList<string> roles;
                try
                {
                    roles = System.Text.Json.JsonSerializer.Deserialize<List<string>>(rolesJson)
                        ?? new List<string>();
                }
                catch (System.Text.Json.JsonException)
                {
                    roles = Array.Empty<string>();
                }

                results.Add(new UserListEntry(
                    UserId: id,
                    Email: email,
                    Username: username,
                    DisplayName: displayName,
                    Status: status,
                    Roles: roles,
                    LastLogin: lastLogin));
            }

            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("identity:read")))
        .WithSummary("List active and invited users for the caller's organisation.");

        // POST /api/v1/identity/users/invite — invite a new user. (AB#1649)
        group.MapPost("/users/invite", async (
            InviteUserRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var error))
                return error!;

            if (string.IsNullOrWhiteSpace(req.Email) || !req.Email.Contains('@'))
            {
                return Results.Json(
                    new { error = "invalid-email", message = "A valid email address is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (!TryGetInviterUserId(ctx, out var inviterUserId, out var inviterError))
                return inviterError!;

            var roles = req.Roles ?? Array.Empty<string>();
            var rolesJson = System.Text.Json.JsonSerializer.Serialize(roles);
            var token = GenerateInvitationToken();
            var expiresAt = DateTime.UtcNow.Add(InvitationLifetime);

            const string sql = """
                INSERT INTO core.user_invitations
                    (org_id, email, invited_by_user_id, roles, token, expires_at)
                VALUES
                    (@org_id, @email, @invited_by_user_id, @roles::jsonb, @token, @expires_at)
                RETURNING invitation_id, token, expires_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@email", req.Email.Trim());
            cmd.Parameters.AddWithValue("@invited_by_user_id", inviterUserId);
            cmd.Parameters.AddWithValue("@roles", rolesJson);
            cmd.Parameters.AddWithValue("@token", token);
            cmd.Parameters.AddWithValue("@expires_at", expiresAt);

            try
            {
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.Json(new { error = "insert-failed" }, statusCode: StatusCodes.Status500InternalServerError);
                }

                var invitationId = reader.GetGuid(0);
                var returnedToken = reader.GetString(1);
                var returnedExpiresAt = reader.GetDateTime(2);

                var response = new InviteUserResponse(
                    InvitationId: invitationId.ToString(),
                    Token: returnedToken,
                    ExpiresAt: returnedExpiresAt.ToString("o"));

                return Results.Created($"/api/v1/identity/users/invite/{invitationId}", response);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                // token collision is essentially impossible with 32 random bytes; surface as 500.
                return Results.Json(
                    new { error = "token-collision", message = ex.MessageText },
                    statusCode: StatusCodes.Status500InternalServerError);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.ForeignKeyViolation)
            {
                return Results.Json(
                    new { error = "invalid-inviter", message = "The inviting user could not be resolved within this org." },
                    statusCode: StatusCodes.Status400BadRequest);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.CheckViolation)
            {
                return Results.Json(
                    new { error = "constraint-violation", message = ex.MessageText },
                    statusCode: StatusCodes.Status400BadRequest);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("identity:write")))
        .WithSummary("Invite a new user to the caller's organisation. Issues a 7-day invitation token.");

        return app;
    }

    private static bool TryGetOrgId(HttpContext ctx, out Guid orgId, out IResult? error)
    {
        orgId = Guid.Empty;
        var orgIdClaim = ctx.User.FindFirstValue("org_id");
        if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out orgId))
        {
            error = Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            return false;
        }
        error = null;
        return true;
    }

    private static bool TryGetInviterUserId(HttpContext ctx, out Guid userId, out IResult? error)
    {
        userId = Guid.Empty;
        // Prefer the standard "sub" claim; fall back to ClaimTypes.NameIdentifier which ASP.NET
        // sometimes maps the JWT sub into during token validation.
        var subClaim = ctx.User.FindFirstValue("sub")
                       ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(subClaim) || !Guid.TryParse(subClaim, out userId))
        {
            error = Results.Json(
                new { error = "missing-user-context", message = "The caller's user id (sub claim) could not be resolved." },
                statusCode: StatusCodes.Status400BadRequest);
            return false;
        }
        error = null;
        return true;
    }

    /// <summary>
    /// Generates a base64url-encoded token from 32 cryptographically random bytes.
    /// Result is URL-safe (no '+', '/', or trailing '=' padding).
    /// </summary>
    private static string GenerateInvitationToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
