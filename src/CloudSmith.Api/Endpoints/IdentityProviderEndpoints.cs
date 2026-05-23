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
/// Identity Provider endpoints — list/configure IdPs for an organisation.
/// AB#1643: GET    /api/v1/identity/idp        — list configured IdPs for the caller's org.
/// AB#1644: POST   /api/v1/identity/idp        — create a new IdP.
/// AB#1645: PUT    /api/v1/identity/idp/{id}   — partial update of an existing IdP.
/// AB#1646: DELETE /api/v1/identity/idp/{id}   — soft-delete (status='disabled'); preserves audit trail.
/// AB#1647: POST   /api/v1/identity/idp/{id}/test — connection test (MVP placeholder).
/// </summary>
public static class IdentityProviderEndpoints
{
    private static readonly HashSet<string> AllowedIdpTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "entra-id", "active-directory", "oidc", "keycloak",
    };

    public sealed record IdentityProviderResponse(
        string Id,
        string Type,
        string DisplayName,
        string Status,
        string? Authority,
        string? ClientId,
        string ConfiguredAt);

    public sealed record CreateIdpRequest(
        string Type,
        string DisplayName,
        string? Authority,
        string? ClientId,
        string? ClientSecret,
        JsonElement? ConfigJson);

    public sealed record UpdateIdpRequest(
        string? Type,
        string? DisplayName,
        string? Authority,
        string? ClientId,
        string? ClientSecret,
        JsonElement? ConfigJson,
        string? Status);

    public sealed record TestIdpResponse(bool Ok, string Message);

    public static IEndpointRouteBuilder MapIdentityProviderEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/identity").WithTags("Identity");

        // GET /api/v1/identity/idp — configured IdPs for the current org. (AB#1643)
        group.MapGet("/idp", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var error))
                return error!;

            const string sql = """
                SELECT idp_id, idp_type, display_name, status, authority, client_id, configured_at
                FROM core.identity_providers
                WHERE org_id = @org_id
                ORDER BY display_name
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var results = new List<IdentityProviderResponse>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                results.Add(ReadResponse(reader));
            }

            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("identity:read")))
        .WithSummary("List configured identity providers for the caller's organisation.");

        // POST /api/v1/identity/idp — create a new IdP. (AB#1644)
        group.MapPost("/idp", async (
            CreateIdpRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var error))
                return error!;

            if (string.IsNullOrWhiteSpace(req.Type) || !AllowedIdpTypes.Contains(req.Type))
            {
                return Results.Json(
                    new { error = "invalid-idp-type", message = $"Type must be one of: {string.Join(", ", AllowedIdpTypes)}." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (string.IsNullOrWhiteSpace(req.DisplayName))
            {
                return Results.Json(
                    new { error = "invalid-display-name", message = "displayName is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var configJsonText = req.ConfigJson is { ValueKind: not JsonValueKind.Undefined and not JsonValueKind.Null }
                ? req.ConfigJson.Value.GetRawText()
                : "{}";

            const string sql = """
                INSERT INTO core.identity_providers
                    (org_id, idp_type, display_name, authority, client_id, client_secret_ref, config_json)
                VALUES
                    (@org_id, @idp_type, @display_name, @authority, @client_id, @client_secret_ref, @config_json::jsonb)
                RETURNING idp_id, idp_type, display_name, status, authority, client_id, configured_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@idp_type", req.Type.ToLowerInvariant());
            cmd.Parameters.AddWithValue("@display_name", req.DisplayName);
            cmd.Parameters.AddWithValue("@authority", (object?)req.Authority ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@client_id", (object?)req.ClientId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@client_secret_ref", (object?)req.ClientSecret ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@config_json", configJsonText);

            try
            {
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.Json(new { error = "insert-failed" }, statusCode: StatusCodes.Status500InternalServerError);
                }
                var response = ReadResponse(reader);
                return Results.Created($"/api/v1/identity/idp/{response.Id}", response);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                return Results.Json(
                    new { error = "duplicate-display-name", message = "An identity provider with that display name already exists for this org." },
                    statusCode: StatusCodes.Status409Conflict);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.CheckViolation)
            {
                return Results.Json(
                    new { error = "constraint-violation", message = ex.MessageText },
                    statusCode: StatusCodes.Status400BadRequest);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("identity:write")))
        .WithSummary("Create a new identity provider for the caller's organisation.");

        // PUT /api/v1/identity/idp/{id} — partial update. (AB#1645)
        group.MapPut("/idp/{id:guid}", async (
            Guid id,
            UpdateIdpRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var error))
                return error!;

            var setClauses = new List<string>();
            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand();
            cmd.Connection = conn;

            if (!string.IsNullOrWhiteSpace(req.Type))
            {
                if (!AllowedIdpTypes.Contains(req.Type))
                {
                    return Results.Json(
                        new { error = "invalid-idp-type", message = $"Type must be one of: {string.Join(", ", AllowedIdpTypes)}." },
                        statusCode: StatusCodes.Status400BadRequest);
                }
                setClauses.Add("idp_type = @idp_type");
                cmd.Parameters.AddWithValue("@idp_type", req.Type.ToLowerInvariant());
            }

            if (!string.IsNullOrWhiteSpace(req.DisplayName))
            {
                setClauses.Add("display_name = @display_name");
                cmd.Parameters.AddWithValue("@display_name", req.DisplayName);
            }

            if (req.Authority is not null)
            {
                setClauses.Add("authority = @authority");
                cmd.Parameters.AddWithValue("@authority", req.Authority.Length == 0 ? (object)DBNull.Value : req.Authority);
            }

            if (req.ClientId is not null)
            {
                setClauses.Add("client_id = @client_id");
                cmd.Parameters.AddWithValue("@client_id", req.ClientId.Length == 0 ? (object)DBNull.Value : req.ClientId);
            }

            if (req.ClientSecret is not null)
            {
                setClauses.Add("client_secret_ref = @client_secret_ref");
                cmd.Parameters.AddWithValue("@client_secret_ref", req.ClientSecret.Length == 0 ? (object)DBNull.Value : req.ClientSecret);
            }

            if (req.ConfigJson is { ValueKind: not JsonValueKind.Undefined and not JsonValueKind.Null } cfg)
            {
                setClauses.Add("config_json = @config_json::jsonb");
                cmd.Parameters.AddWithValue("@config_json", cfg.GetRawText());
            }

            if (!string.IsNullOrWhiteSpace(req.Status))
            {
                var status = req.Status.ToLowerInvariant();
                if (status is not ("configured" or "verified" or "disabled" or "error"))
                {
                    return Results.Json(
                        new { error = "invalid-status", message = "Status must be one of: configured, verified, disabled, error." },
                        statusCode: StatusCodes.Status400BadRequest);
                }
                setClauses.Add("status = @status");
                cmd.Parameters.AddWithValue("@status", status);
            }

            if (setClauses.Count == 0)
            {
                return Results.Json(
                    new { error = "empty-update", message = "At least one field must be provided." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            setClauses.Add("updated_at = now()");

            cmd.CommandText = $"""
                UPDATE core.identity_providers
                SET {string.Join(", ", setClauses)}
                WHERE idp_id = @idp_id AND org_id = @org_id
                RETURNING idp_id, idp_type, display_name, status, authority, client_id, configured_at
                """;
            cmd.Parameters.AddWithValue("@idp_id", id);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            try
            {
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.NotFound(new { error = "idp-not-found" });
                }
                return Results.Ok(ReadResponse(reader));
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                return Results.Json(
                    new { error = "duplicate-display-name", message = "An identity provider with that display name already exists for this org." },
                    statusCode: StatusCodes.Status409Conflict);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.CheckViolation)
            {
                return Results.Json(
                    new { error = "constraint-violation", message = ex.MessageText },
                    statusCode: StatusCodes.Status400BadRequest);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("identity:write")))
        .WithSummary("Update an identity provider (partial). Bumps updated_at.");

        // DELETE /api/v1/identity/idp/{id} — soft-delete by setting status='disabled'. (AB#1646)
        // Local admin break-glass remains active per ADR-047, so a 0-active-IdP state is acceptable.
        group.MapDelete("/idp/{id:guid}", async (
            Guid id,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var error))
                return error!;

            const string sql = """
                UPDATE core.identity_providers
                SET status = 'disabled', updated_at = now()
                WHERE idp_id = @idp_id AND org_id = @org_id
                RETURNING idp_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@idp_id", id);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var result = await cmd.ExecuteScalarAsync(ct);
            if (result is null || result is DBNull)
            {
                return Results.NotFound(new { error = "idp-not-found" });
            }

            return Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("identity:write")))
        .WithSummary("Soft-delete an identity provider (status='disabled'); preserves audit trail.");

        // POST /api/v1/identity/idp/{id}/test — connection test. MVP placeholder. (AB#1647)
        group.MapPost("/idp/{id:guid}/test", async (
            Guid id,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var error))
                return error!;

            // Confirm the IdP exists and belongs to this org before returning the placeholder.
            const string sql = """
                SELECT 1 FROM core.identity_providers
                WHERE idp_id = @idp_id AND org_id = @org_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@idp_id", id);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var exists = await cmd.ExecuteScalarAsync(ct);
            if (exists is null || exists is DBNull)
            {
                return Results.NotFound(new { error = "idp-not-found" });
            }

            // P1 follow-up: call the IdP's discovery endpoint (/.well-known/openid-configuration)
            // and validate client credentials with a client_credentials token request.
            return Results.Ok(new TestIdpResponse(
                Ok: true,
                Message: "Connection test not yet implemented; placeholder returns success"));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("identity:write")))
        .WithSummary("Test the connection to a configured identity provider (MVP placeholder).");

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

    private static IdentityProviderResponse ReadResponse(NpgsqlDataReader reader)
    {
        var idpId = reader.GetGuid(0);
        var idpType = reader.GetString(1);
        var displayName = reader.GetString(2);
        var dbStatus = reader.GetString(3);
        var authority = reader.IsDBNull(4) ? null : reader.GetString(4);
        var clientId = reader.IsDBNull(5) ? null : reader.GetString(5);
        var configuredAt = reader.GetDateTime(6);

        return new IdentityProviderResponse(
            Id: idpId.ToString(),
            Type: idpType,
            DisplayName: displayName,
            Status: MapStatus(dbStatus),
            Authority: authority,
            ClientId: clientId,
            ConfiguredAt: configuredAt.ToString("o"));
    }

    /// <summary>
    /// Maps the DB status enum (configured/verified/disabled/error) to its capitalised
    /// portal-facing form (Configured/Verified/Disabled/Error).
    /// </summary>
    private static string MapStatus(string dbStatus) => dbStatus?.ToLowerInvariant() switch
    {
        "configured" => "Configured",
        "verified" => "Verified",
        "disabled" => "Disabled",
        "error" => "Error",
        _ => "Configured",
    };
}
