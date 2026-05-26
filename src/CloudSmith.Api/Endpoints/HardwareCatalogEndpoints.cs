// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using System.Text.Json;
using CloudSmith.Api.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Hardware catalog and drift detection endpoints (AB#1496).
///
/// GET  /api/v1/hardware-catalog/profiles              — list hardware profiles
/// GET  /api/v1/hardware-catalog/profiles/{profileId}  — get profile detail
/// POST /api/v1/hardware-catalog/profiles              — create profile
/// PUT  /api/v1/hardware-catalog/profiles/{profileId}  — update profile
/// DELETE /api/v1/hardware-catalog/profiles/{profileId} — delete profile
///
/// GET  /api/v1/drift                             — list drift reports
/// GET  /api/v1/drift/{driftReportId}             — get drift report detail
/// POST /api/v1/drift/{driftReportId}/acknowledge  — acknowledge a drift report
/// </summary>
public static class HardwareCatalogEndpoints
{
    public static IEndpointRouteBuilder MapHardwareCatalogEndpoints(this IEndpointRouteBuilder app)
    {
        // --- Hardware profile catalog ---
        var catalog = app.MapGroup("/api/v1/hardware-catalog").RequireAuthorization().WithTags("HardwareCatalog");

        // GET /api/v1/hardware-catalog/profiles
        catalog.MapGet("/profiles", async (
            HttpContext ctx,
            NpgsqlDataSource db,
            string? manufacturer,
            string? model,
            string? search,
            int page = 1, int pageSize = 25,
            CancellationToken ct = default) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            page     = Math.Max(1, page);
            pageSize = Math.Clamp(pageSize, 1, 100);

            var conditions = new List<string> { "org_id = @org_id" };
            if (!string.IsNullOrWhiteSpace(manufacturer)) conditions.Add("manufacturer ILIKE @manufacturer");
            if (!string.IsNullOrWhiteSpace(model))        conditions.Add("model ILIKE @model");
            if (!string.IsNullOrWhiteSpace(search))       conditions.Add("(name ILIKE @search OR model ILIKE @search)");

            var where = string.Join(" AND ", conditions);

            await using var conn = await db.OpenConnectionAsync(ct);

            await using var countCmd = new NpgsqlCommand(
                $"SELECT COUNT(*) FROM inventory.hardware_catalog_profiles WHERE {where}", conn);
            AddParams(countCmd, orgId, manufacturer, model, search);
            var total = Convert.ToInt32(await countCmd.ExecuteScalarAsync(ct));

            await using var cmd = new NpgsqlCommand($"""
                SELECT profile_id, name, manufacturer, model, os_version_target,
                       jsonb_array_length(components_json) AS component_count, created_at, updated_at
                FROM inventory.hardware_catalog_profiles
                WHERE {where}
                ORDER BY name
                LIMIT @limit OFFSET @offset
                """, conn);
            AddParams(cmd, orgId, manufacturer, model, search);
            cmd.Parameters.AddWithValue("@limit",  pageSize);
            cmd.Parameters.AddWithValue("@offset", (page - 1) * pageSize);

            var items = new List<object>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                items.Add(new
                {
                    profileId        = reader.GetGuid(0),
                    name             = reader.GetString(1),
                    manufacturer     = reader.IsDBNull(2) ? null : reader.GetString(2),
                    model            = reader.IsDBNull(3) ? null : reader.GetString(3),
                    osVersionTarget  = reader.IsDBNull(4) ? null : reader.GetString(4),
                    componentCount   = reader.GetInt32(5),
                    createdAt        = reader.GetFieldValue<DateTimeOffset>(6),
                    updatedAt        = reader.GetFieldValue<DateTimeOffset>(7),
                });
            }

            return Results.Ok(new
            {
                items,
                pagination = new { page, pageSize, totalItems = total, totalPages = (int)Math.Ceiling((double)total / pageSize) },
            });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("inventory.catalog.read")))
        .WithSummary("List hardware baseline profiles for the caller's org.");

        // GET /api/v1/hardware-catalog/profiles/{profileId}
        catalog.MapGet("/profiles/{profileId:guid}", async (
            Guid profileId,
            HttpContext ctx,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();

            const string sql = """
                SELECT profile_id, name, manufacturer, model, os_version_target,
                       description, components_json, created_by_user_id, created_at, updated_at
                FROM inventory.hardware_catalog_profiles
                WHERE profile_id = @profile_id AND org_id = @org_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@profile_id", profileId);
            cmd.Parameters.AddWithValue("@org_id",     orgId);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                return Results.NotFound(new { error = "profile-not-found" });

            var componentsJson = reader.IsDBNull(6) ? "[]" : reader.GetString(6);
            var components     = JsonSerializer.Deserialize<JsonElement>(componentsJson);

            return Results.Ok(new
            {
                profileId        = reader.GetGuid(0),
                name             = reader.GetString(1),
                manufacturer     = reader.IsDBNull(2) ? null : reader.GetString(2),
                model            = reader.IsDBNull(3) ? null : reader.GetString(3),
                osVersionTarget  = reader.IsDBNull(4) ? null : reader.GetString(4),
                description      = reader.IsDBNull(5) ? null : reader.GetString(5),
                components,
                createdByUserId  = reader.IsDBNull(7) ? (Guid?)null : reader.GetGuid(7),
                createdAt        = reader.GetFieldValue<DateTimeOffset>(8),
                updatedAt        = reader.GetFieldValue<DateTimeOffset>(9),
            });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("inventory.catalog.read")))
        .WithSummary("Get a hardware baseline profile by ID.");

        // POST /api/v1/hardware-catalog/profiles
        catalog.MapPost("/profiles", async (
            CreateProfileRequest req,
            HttpContext ctx,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId))   return Results.Unauthorized();
            if (!TryGetUserId(ctx, out var userId))  return Results.Unauthorized();
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { error = "name-required" });

            var componentsJson = req.Components is { ValueKind: not JsonValueKind.Undefined } c
                ? c.GetRawText() : "[]";

            const string sql = """
                INSERT INTO inventory.hardware_catalog_profiles
                    (org_id, name, manufacturer, model, os_version_target, description, components_json, created_by_user_id)
                VALUES
                    (@org_id, @name, @manufacturer, @model, @os_version, @description, @components::jsonb, @created_by)
                RETURNING profile_id, name, created_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id",       orgId);
            cmd.Parameters.AddWithValue("@name",         req.Name);
            cmd.Parameters.AddWithValue("@manufacturer", (object?)req.Manufacturer ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@model",        (object?)req.Model ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@os_version",   (object?)req.OsVersionTarget ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@description",  (object?)req.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@components",   componentsJson);
            cmd.Parameters.AddWithValue("@created_by",   (object?)userId ?? DBNull.Value);

            try
            {
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                await reader.ReadAsync(ct);
                var id = reader.GetGuid(0);
                return Results.Created($"/api/v1/hardware-catalog/profiles/{id}", new { profileId = id, name = reader.GetString(1), createdAt = reader.GetFieldValue<DateTimeOffset>(2) });
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                return Results.Conflict(new { error = "duplicate-profile-name" });
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("inventory.catalog.write")))
        .WithSummary("Create a hardware baseline profile.");

        // DELETE /api/v1/hardware-catalog/profiles/{profileId}
        catalog.MapDelete("/profiles/{profileId:guid}", async (
            Guid profileId,
            HttpContext ctx,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(
                "DELETE FROM inventory.hardware_catalog_profiles WHERE profile_id = @id AND org_id = @org_id RETURNING profile_id",
                conn);
            cmd.Parameters.AddWithValue("@id",     profileId);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is null ? Results.NotFound(new { error = "profile-not-found" }) : Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("inventory.catalog.write")))
        .WithSummary("Delete a hardware baseline profile.");

        // --- Drift detection ---
        var drift = app.MapGroup("/api/v1/drift").RequireAuthorization().WithTags("Drift");

        // GET /api/v1/drift
        drift.MapGet("/", async (
            HttpContext ctx,
            NpgsqlDataSource db,
            Guid? clusterId,
            Guid? nodeId,
            string? severity,
            bool? acknowledged,
            DateTimeOffset? from,
            DateTimeOffset? to,
            int page = 1, int pageSize = 25,
            CancellationToken ct = default) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            page     = Math.Max(1, page);
            pageSize = Math.Clamp(pageSize, 1, 100);

            var conditions = new List<string> { "org_id = @org_id" };
            if (clusterId.HasValue)    conditions.Add("cluster_id = @cluster_id");
            if (nodeId.HasValue)       conditions.Add("node_id = @node_id");
            if (!string.IsNullOrWhiteSpace(severity)) conditions.Add("highest_severity = @severity");
            if (acknowledged.HasValue) conditions.Add("acknowledged = @acknowledged");
            if (from.HasValue)         conditions.Add("detected_at >= @from");
            if (to.HasValue)           conditions.Add("detected_at <= @to");

            var where = string.Join(" AND ", conditions);

            await using var conn = await db.OpenConnectionAsync(ct);

            await using var countCmd = new NpgsqlCommand(
                $"SELECT COUNT(*) FROM inventory.drift_reports WHERE {where}", conn);
            AddDriftParams(countCmd, orgId, clusterId, nodeId, severity, acknowledged, from, to);
            var total = Convert.ToInt32(await countCmd.ExecuteScalarAsync(ct));

            await using var cmd = new NpgsqlCommand($"""
                SELECT drift_report_id, run_id, cluster_id, cluster_name, node_id, node_name,
                       change_count, highest_severity, acknowledged, detected_at
                FROM inventory.drift_reports
                WHERE {where}
                ORDER BY detected_at DESC
                LIMIT @limit OFFSET @offset
                """, conn);
            AddDriftParams(cmd, orgId, clusterId, nodeId, severity, acknowledged, from, to);
            cmd.Parameters.AddWithValue("@limit",  pageSize);
            cmd.Parameters.AddWithValue("@offset", (page - 1) * pageSize);

            var items = new List<object>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                items.Add(new
                {
                    driftReportId    = reader.GetGuid(0),
                    runId            = reader.IsDBNull(1) ? (Guid?)null : reader.GetGuid(1),
                    clusterId        = reader.GetGuid(2),
                    clusterName      = reader.IsDBNull(3) ? null : reader.GetString(3),
                    nodeId           = reader.GetGuid(4),
                    nodeName         = reader.IsDBNull(5) ? null : reader.GetString(5),
                    changeCount      = reader.GetInt32(6),
                    highestSeverity  = reader.GetString(7),
                    acknowledged     = reader.GetBoolean(8),
                    detectedAt       = reader.GetFieldValue<DateTimeOffset>(9),
                });
            }

            return Results.Ok(new
            {
                items,
                pagination = new { page, pageSize, totalItems = total, totalPages = (int)Math.Ceiling((double)total / pageSize) },
            });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("inventory.drift.read")))
        .WithSummary("List drift reports for the caller's org.");

        // GET /api/v1/drift/{driftReportId}
        drift.MapGet("/{driftReportId:guid}", async (
            Guid driftReportId,
            HttpContext ctx,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();

            await using var conn = await db.OpenConnectionAsync(ct);

            DriftReportDetail? report = null;
            await using (var cmd = new NpgsqlCommand("""
                SELECT drift_report_id, run_id, cluster_id, node_id, node_name,
                       change_count, highest_severity, acknowledged, acknowledged_at,
                       acknowledged_by, acknowledge_note, detected_at
                FROM inventory.drift_reports
                WHERE drift_report_id = @id AND org_id = @org_id
                """, conn))
            {
                cmd.Parameters.AddWithValue("@id",     driftReportId);
                cmd.Parameters.AddWithValue("@org_id", orgId);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                    return Results.NotFound(new { error = "drift-report-not-found" });

                report = new DriftReportDetail(
                    DriftReportId:  reader.GetGuid(0),
                    RunId:          reader.IsDBNull(1) ? (Guid?)null : reader.GetGuid(1),
                    ClusterId:      reader.GetGuid(2),
                    NodeId:         reader.GetGuid(3),
                    NodeName:       reader.IsDBNull(4) ? null : reader.GetString(4),
                    ChangeCount:    reader.GetInt32(5),
                    HighestSeverity:reader.GetString(6),
                    Acknowledged:   reader.GetBoolean(7),
                    AcknowledgedAt: reader.IsDBNull(8) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(8),
                    AcknowledgedBy: reader.IsDBNull(9) ? (Guid?)null : reader.GetGuid(9),
                    AcknowledgeNote:reader.IsDBNull(10) ? null : reader.GetString(10),
                    DetectedAt:     reader.GetFieldValue<DateTimeOffset>(11));
            }

            var items = new List<object>();
            await using (var cmd = new NpgsqlCommand("""
                SELECT drift_item_id, entity_type, entity_name, change_type, field_name,
                       previous_value, current_value, severity, acknowledged
                FROM inventory.drift_items
                WHERE drift_report_id = @id AND org_id = @org_id
                ORDER BY severity DESC, entity_name
                """, conn))
            {
                cmd.Parameters.AddWithValue("@id",     driftReportId);
                cmd.Parameters.AddWithValue("@org_id", orgId);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    items.Add(new
                    {
                        driftItemId    = reader.GetGuid(0),
                        entityType     = reader.GetString(1),
                        entityName     = reader.GetString(2),
                        changeType     = reader.GetString(3),
                        fieldName      = reader.GetString(4),
                        previousValue  = reader.IsDBNull(5) ? null : reader.GetString(5),
                        currentValue   = reader.IsDBNull(6) ? null : reader.GetString(6),
                        severity       = reader.GetString(7),
                        acknowledged   = reader.GetBoolean(8),
                    });
                }
            }

            return Results.Ok(new
            {
                report.DriftReportId,
                report.RunId,
                report.ClusterId,
                report.NodeId,
                report.NodeName,
                report.ChangeCount,
                report.HighestSeverity,
                report.Acknowledged,
                report.AcknowledgedAt,
                report.AcknowledgedBy,
                report.AcknowledgeNote,
                report.DetectedAt,
                items,
            });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("inventory.drift.read")))
        .WithSummary("Get a drift report with all change items.");

        // POST /api/v1/drift/{driftReportId}/acknowledge
        drift.MapPost("/{driftReportId:guid}/acknowledge", async (
            Guid driftReportId,
            AcknowledgeDriftRequest req,
            HttpContext ctx,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId))   return Results.Unauthorized();
            if (!TryGetUserId(ctx, out var userId))  return Results.Unauthorized();

            const string sql = """
                UPDATE inventory.drift_reports
                SET acknowledged     = true,
                    acknowledged_at  = now(),
                    acknowledged_by  = @user_id,
                    acknowledge_note = @note
                WHERE drift_report_id = @id AND org_id = @org_id
                RETURNING drift_report_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd  = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@id",      driftReportId);
            cmd.Parameters.AddWithValue("@org_id",  orgId);
            cmd.Parameters.AddWithValue("@user_id", userId);
            cmd.Parameters.AddWithValue("@note",    (object?)req.Note ?? DBNull.Value);
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is null ? Results.NotFound(new { error = "drift-report-not-found" }) : Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("inventory.drift.write")))
        .WithSummary("Acknowledge a drift report.");

        return app;
    }

    // --- Helpers ---

    private static bool TryGetOrgId(HttpContext ctx, out Guid orgId)
    {
        if (ctx.Items["OrgId"] is Guid id) { orgId = id; return true; }
        orgId = default;
        return false;
    }

    private static bool TryGetUserId(HttpContext ctx, out Guid userId)
    {
        if (ctx.Items["UserId"] is Guid id) { userId = id; return true; }
        var raw = ctx.User.FindFirstValue("sub") ?? ctx.User.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier);
        if (Guid.TryParse(raw, out userId)) return true;
        userId = default;
        return false;
    }

    private static void AddParams(NpgsqlCommand cmd, Guid orgId,
        string? manufacturer, string? model, string? search)
    {
        cmd.Parameters.AddWithValue("@org_id", orgId);
        if (manufacturer != null) cmd.Parameters.AddWithValue("@manufacturer", $"{manufacturer}%");
        if (model != null)        cmd.Parameters.AddWithValue("@model", $"{model}%");
        if (search != null)       cmd.Parameters.AddWithValue("@search", $"%{search}%");
    }

    private static void AddDriftParams(NpgsqlCommand cmd, Guid orgId,
        Guid? clusterId, Guid? nodeId, string? severity, bool? acknowledged,
        DateTimeOffset? from, DateTimeOffset? to)
    {
        cmd.Parameters.AddWithValue("@org_id", orgId);
        if (clusterId.HasValue)    cmd.Parameters.AddWithValue("@cluster_id",  clusterId.Value);
        if (nodeId.HasValue)       cmd.Parameters.AddWithValue("@node_id",     nodeId.Value);
        if (severity != null)      cmd.Parameters.AddWithValue("@severity",    severity);
        if (acknowledged.HasValue) cmd.Parameters.AddWithValue("@acknowledged",acknowledged.Value);
        if (from.HasValue)         cmd.Parameters.AddWithValue("@from",        from.Value);
        if (to.HasValue)           cmd.Parameters.AddWithValue("@to",          to.Value);
    }

    // --- Request/response types ---

    public sealed record CreateProfileRequest(
        string  Name,
        string? Manufacturer,
        string? Model,
        string? OsVersionTarget,
        string? Description,
        JsonElement? Components);

    public sealed record AcknowledgeDriftRequest(string? Note);

    private sealed record DriftReportDetail(
        Guid DriftReportId, Guid? RunId, Guid ClusterId, Guid NodeId,
        string? NodeName, int ChangeCount, string HighestSeverity,
        bool Acknowledged, DateTimeOffset? AcknowledgedAt,
        Guid? AcknowledgedBy, string? AcknowledgeNote, DateTimeOffset DetectedAt);
}
