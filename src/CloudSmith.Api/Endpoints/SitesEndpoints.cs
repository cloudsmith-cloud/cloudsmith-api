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
/// Sites CRUD endpoints (AB#1652). Sites are operator-defined physical/logical locations
/// scoped to the caller's organisation. Backed by core.sites.
/// </summary>
public static class SitesEndpoints
{
    public sealed record SiteResponse(
        Guid SiteId,
        string Name,
        string? Description,
        string? Location,
        string CreatedAt,
        string UpdatedAt);

    public sealed record CreateSiteRequest(string Name, string? Description, string? Location);

    public sealed record UpdateSiteRequest(string? Name, string? Description, string? Location);

    public static IEndpointRouteBuilder MapSitesEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/platform/sites").WithTags("Sites");

        // GET /api/v1/platform/sites — list sites for the caller's org.
        group.MapGet("/", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
            {
                return orgError!;
            }

            const string sql = """
                SELECT site_id, name, description, location, created_at, updated_at
                FROM core.sites
                WHERE org_id = @org_id
                ORDER BY name
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var results = new List<SiteResponse>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                results.Add(new SiteResponse(
                    SiteId: reader.GetGuid(0),
                    Name: reader.GetString(1),
                    Description: reader.IsDBNull(2) ? null : reader.GetString(2),
                    Location: reader.IsDBNull(3) ? null : reader.GetString(3),
                    CreatedAt: reader.GetDateTime(4).ToString("o"),
                    UpdatedAt: reader.GetDateTime(5).ToString("o")));
            }

            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("List sites for the caller's organisation.");

        // GET /api/v1/platform/sites/{siteId} — get a single site.
        group.MapGet("/{siteId:guid}", async (
            Guid siteId,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
                return orgError!;

            const string sql = """
                SELECT site_id, name, description, location, created_at, updated_at
                FROM core.sites
                WHERE org_id = @org_id AND site_id = @site_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id",  orgId);
            cmd.Parameters.AddWithValue("@site_id", siteId);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                return Results.NotFound(new { error = "site-not-found", siteId });

            return Results.Ok(new SiteResponse(
                SiteId:      reader.GetGuid(0),
                Name:        reader.GetString(1),
                Description: reader.IsDBNull(2) ? null : reader.GetString(2),
                Location:    reader.IsDBNull(3) ? null : reader.GetString(3),
                CreatedAt:   reader.GetDateTime(4).ToString("o"),
                UpdatedAt:   reader.GetDateTime(5).ToString("o")));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("Get a single site by ID.");

        // POST /api/v1/platform/sites — create a site.
        group.MapPost("/", async (
            CreateSiteRequest request,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
            {
                return orgError!;
            }

            if (string.IsNullOrWhiteSpace(request.Name))
            {
                return Results.Json(
                    new { error = "invalid-request", message = "name is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                INSERT INTO core.sites (org_id, name, description, location)
                VALUES (@org_id, @name, @description, @location)
                RETURNING site_id, name, description, location, created_at, updated_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@name", request.Name);
            cmd.Parameters.AddWithValue("@description", (object?)request.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@location", (object?)request.Location ?? DBNull.Value);

            try
            {
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.Json(new { error = "insert-failed" }, statusCode: StatusCodes.Status500InternalServerError);
                }

                var response = new SiteResponse(
                    SiteId: reader.GetGuid(0),
                    Name: reader.GetString(1),
                    Description: reader.IsDBNull(2) ? null : reader.GetString(2),
                    Location: reader.IsDBNull(3) ? null : reader.GetString(3),
                    CreatedAt: reader.GetDateTime(4).ToString("o"),
                    UpdatedAt: reader.GetDateTime(5).ToString("o"));

                return Results.Created($"/api/v1/platform/sites/{response.SiteId}", response);
            }
            catch (PostgresException pex) when (pex.SqlState == "23505")
            {
                return Results.Json(
                    new { error = "site-name-conflict", name = request.Name },
                    statusCode: StatusCodes.Status409Conflict);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Create a site for the caller's organisation.");

        // PUT /api/v1/platform/sites/{siteId} — partial update.
        group.MapPut("/{siteId:guid}", async (
            Guid siteId,
            UpdateSiteRequest request,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
            {
                return orgError!;
            }

            // Partial update: only patch fields the caller actually supplied.
            // Description / location are nullable strings — null means "leave unchanged"
            // since we cannot distinguish "set to null" from "not supplied" in JSON.
            // Operators wanting to clear a field can set it to "" (empty string).
            if (request.Name is null && request.Description is null && request.Location is null)
            {
                return Results.Json(
                    new { error = "invalid-request", message = "at least one of name, description, or location is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (request.Name is not null && string.IsNullOrWhiteSpace(request.Name))
            {
                return Results.Json(
                    new { error = "invalid-request", message = "name cannot be blank." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                UPDATE core.sites
                SET name        = COALESCE(@name, name),
                    description = COALESCE(@description, description),
                    location    = COALESCE(@location, location),
                    updated_at  = now()
                WHERE org_id = @org_id AND site_id = @site_id
                RETURNING site_id, name, description, location, created_at, updated_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@site_id", siteId);
            cmd.Parameters.AddWithValue("@name", (object?)request.Name ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@description", (object?)request.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@location", (object?)request.Location ?? DBNull.Value);

            try
            {
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.NotFound(new { error = "site-not-found", siteId });
                }

                var response = new SiteResponse(
                    SiteId: reader.GetGuid(0),
                    Name: reader.GetString(1),
                    Description: reader.IsDBNull(2) ? null : reader.GetString(2),
                    Location: reader.IsDBNull(3) ? null : reader.GetString(3),
                    CreatedAt: reader.GetDateTime(4).ToString("o"),
                    UpdatedAt: reader.GetDateTime(5).ToString("o"));

                return Results.Ok(response);
            }
            catch (PostgresException pex) when (pex.SqlState == "23505")
            {
                return Results.Json(
                    new { error = "site-name-conflict", name = request.Name },
                    statusCode: StatusCodes.Status409Conflict);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Partially update a site for the caller's organisation.");

        // DELETE /api/v1/platform/sites/{siteId} — physical delete.
        group.MapDelete("/{siteId:guid}", async (
            Guid siteId,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
            {
                return orgError!;
            }

            const string sql = """
                DELETE FROM core.sites
                WHERE org_id = @org_id AND site_id = @site_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@site_id", siteId);

            var rows = await cmd.ExecuteNonQueryAsync(ct);
            if (rows == 0)
            {
                return Results.NotFound(new { error = "site-not-found", siteId });
            }

            return Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Physically delete a site (sites have no audit-trail requirement).");

        return app;
    }

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
