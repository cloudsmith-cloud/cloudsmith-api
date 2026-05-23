// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using CloudSmith.Api.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Secrets references CRUD endpoints (AB#1653). Secret refs are pointers to externally-held
/// secret material (Key Vault entries, locally-encrypted blobs, Keycloak client secrets,
/// or manually-tracked values). Backed by core.secret_refs.
/// </summary>
public static class SecretsEndpoints
{
    private static readonly HashSet<string> AllowedRefTypes = new(StringComparer.Ordinal)
    {
        "api-key", "client-secret", "connection-string", "certificate", "arbitrary",
    };

    private static readonly HashSet<string> AllowedProviders = new(StringComparer.Ordinal)
    {
        "key-vault", "local-encrypted", "keycloak", "manual",
    };

    public sealed record SecretRefResponse(
        Guid SecretRefId,
        string Name,
        string RefType,
        string Provider,
        string? VaultName,
        string? SecretPath,
        string? Version,
        string? LastRotatedAt,
        string CreatedAt,
        string UpdatedAt);

    public sealed record CreateSecretRefRequest(
        string Name,
        string RefType,
        string Provider,
        string? VaultName,
        string? SecretPath,
        string? Version);

    public static IEndpointRouteBuilder MapSecretsEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/secrets").WithTags("Secrets");

        // GET /api/v1/secrets/refs — list secret refs for the caller's org.
        group.MapGet("/refs", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
            {
                return orgError!;
            }

            const string sql = """
                SELECT secret_ref_id, name, ref_type, provider, vault_name, secret_path, version,
                       last_rotated_at, created_at, updated_at
                FROM core.secret_refs
                WHERE org_id = @org_id
                ORDER BY name
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var results = new List<SecretRefResponse>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                results.Add(ReadRow(reader));
            }

            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("secrets:read")))
        .WithSummary("List secret references for the caller's organisation.");

        // POST /api/v1/secrets/refs — create a new secret ref.
        group.MapPost("/refs", async (
            CreateSecretRefRequest request,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
            {
                return orgError!;
            }

            if (string.IsNullOrWhiteSpace(request.Name)
                || string.IsNullOrWhiteSpace(request.RefType)
                || string.IsNullOrWhiteSpace(request.Provider))
            {
                return Results.Json(
                    new { error = "invalid-request", message = "name, refType, and provider are required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (!AllowedRefTypes.Contains(request.RefType))
            {
                return Results.Json(
                    new { error = "invalid-ref-type", allowed = AllowedRefTypes },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (!AllowedProviders.Contains(request.Provider))
            {
                return Results.Json(
                    new { error = "invalid-provider", allowed = AllowedProviders },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                INSERT INTO core.secret_refs
                    (org_id, name, ref_type, provider, vault_name, secret_path, version)
                VALUES
                    (@org_id, @name, @ref_type, @provider, @vault_name, @secret_path, @version)
                RETURNING secret_ref_id, name, ref_type, provider, vault_name, secret_path, version,
                          last_rotated_at, created_at, updated_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@name", request.Name);
            cmd.Parameters.AddWithValue("@ref_type", request.RefType);
            cmd.Parameters.AddWithValue("@provider", request.Provider);
            cmd.Parameters.AddWithValue("@vault_name", (object?)request.VaultName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@secret_path", (object?)request.SecretPath ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@version", (object?)request.Version ?? DBNull.Value);

            try
            {
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.Json(new { error = "insert-failed" }, statusCode: StatusCodes.Status500InternalServerError);
                }

                var response = ReadRow(reader);
                return Results.Created($"/api/v1/secrets/refs/{response.SecretRefId}", response);
            }
            catch (PostgresException pex) when (pex.SqlState == "23505")
            {
                return Results.Json(
                    new { error = "secret-ref-name-conflict", name = request.Name },
                    statusCode: StatusCodes.Status409Conflict);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("secrets:write")))
        .WithSummary("Create a secret reference for the caller's organisation.");

        // DELETE /api/v1/secrets/refs/{secretRefId} — physical delete.
        // MVP: no reference-graph check; just delete. Phase V will gate this on usage.
        group.MapDelete("/refs/{secretRefId:guid}", async (
            Guid secretRefId,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
            {
                return orgError!;
            }

            const string sql = """
                DELETE FROM core.secret_refs
                WHERE org_id = @org_id AND secret_ref_id = @secret_ref_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@secret_ref_id", secretRefId);

            var rows = await cmd.ExecuteNonQueryAsync(ct);
            if (rows == 0)
            {
                return Results.NotFound(new { error = "secret-ref-not-found", secretRefId });
            }

            return Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("secrets:write")))
        .WithSummary("Physically delete a secret reference for the caller's organisation.");

        // POST /api/v1/secrets/refs/{secretRefId}/rotate — MVP placeholder.
        // Real rotation pipeline (provider call + new version capture) lands in Phase V.
        // For now we just stamp last_rotated_at=now() so the portal can show "recently rotated".
        group.MapPost("/refs/{secretRefId:guid}/rotate", async (
            Guid secretRefId,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
            {
                return orgError!;
            }

            const string sql = """
                UPDATE core.secret_refs
                SET last_rotated_at = now(),
                    updated_at      = now()
                WHERE org_id = @org_id AND secret_ref_id = @secret_ref_id
                RETURNING secret_ref_id, name, ref_type, provider, vault_name, secret_path, version,
                          last_rotated_at, created_at, updated_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@secret_ref_id", secretRefId);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                return Results.NotFound(new { error = "secret-ref-not-found", secretRefId });
            }

            return Results.Ok(ReadRow(reader));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("secrets:write")))
        .WithSummary("Mark a secret reference as rotated (MVP placeholder — stamps last_rotated_at only).");

        return app;
    }

    private static SecretRefResponse ReadRow(NpgsqlDataReader reader) => new(
        SecretRefId: reader.GetGuid(0),
        Name: reader.GetString(1),
        RefType: reader.GetString(2),
        Provider: reader.GetString(3),
        VaultName: reader.IsDBNull(4) ? null : reader.GetString(4),
        SecretPath: reader.IsDBNull(5) ? null : reader.GetString(5),
        Version: reader.IsDBNull(6) ? null : reader.GetString(6),
        LastRotatedAt: reader.IsDBNull(7) ? null : reader.GetDateTime(7).ToString("o"),
        CreatedAt: reader.GetDateTime(8).ToString("o"),
        UpdatedAt: reader.GetDateTime(9).ToString("o"));

    private static bool TryGetOrgId(HttpContext ctx, out Guid orgId, out IResult? error)
    {
        var orgIdClaim = ctx.User.FindFirstValue("org_id");
        if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out orgId))
        {
            orgId = Guid.Empty;
            error = Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            return false;
        }

        error = null;
        return true;
    }
}
