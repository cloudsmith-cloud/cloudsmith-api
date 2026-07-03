// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using System.Text.Json;
using CloudSmith.Api.Authorization;
using CloudSmith.Api.Services.Jobs;
using CloudSmith.Core.Jobs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Job batch endpoints — AB#4843 (supersedes the AB#1931 in-process processor).
/// Batch = aggregation over core.jobs (design/api-surface/job-batch-endpoints.md):
/// every batch item creates a core.jobs row at batch creation time and the child
/// jobs enter the normal canonical dispatch pipeline. Batch/item status is a pure
/// aggregation of child job states — there is no batch-side execution path.
///
///   POST /api/v1/jobs/batch                 jobs:write   create batch + child jobs (202)
///   GET  /api/v1/jobs/batch/{batchId}       jobs:read    header + aggregated status
///   GET  /api/v1/jobs/batch/{batchId}/items jobs:read    paginated items with child jobIds
/// </summary>
public static class JobBatchEndpoints
{
    /// <summary>
    /// Default absolute deadline for batch child jobs (contract: timeout_at is set
    /// at creation; the API watchdog adjudicates). Callers get per-job control when
    /// the create-job API surfaces it — Wave 1 batches use this fixed window.
    /// </summary>
    private static readonly TimeSpan DefaultJobTimeout = TimeSpan.FromHours(1);

    public sealed record JobBatchRequest(
        string Operation,
        IReadOnlyList<string> ResourceIds,
        JsonElement? Parameters,
        string? IdempotencyKey = null);

    public sealed record JobBatchCreatedResponse(
        string BatchId,
        string Status,
        int TotalItems);

    public static IEndpointRouteBuilder MapJobBatchEndpoints(this IEndpointRouteBuilder app)
    {
        var jobs = app.MapGroup("/api/v1/jobs").WithTags("Jobs");

        // POST /api/v1/jobs/batch — insert batch header + one core.jobs row per
        // resourceId + linking items, all in one transaction (design §POST).
        jobs.MapPost("/batch", async (
            JobBatchRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var subClaim = ctx.User.FindFirstValue("sub")
                ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(subClaim) || !Guid.TryParse(subClaim, out var userId))
            {
                return Results.Json(new { error = "missing-user-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            if (string.IsNullOrWhiteSpace(req.Operation))
            {
                return Results.Json(
                    new { error = "invalid-operation", message = "operation is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (req.ResourceIds is null || req.ResourceIds.Count == 0)
            {
                return Results.Json(
                    new { error = "invalid-resourceIds", message = "resourceIds must contain at least one entry." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (req.ResourceIds.Count > 500)
            {
                return Results.Problem(
                    title: "Batch too large",
                    detail: "Maximum 500 items per batch.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var parametersJson = req.Parameters is { ValueKind: not JsonValueKind.Undefined and not JsonValueKind.Null }
                ? req.Parameters.Value.GetRawText()
                : null;

            await using var conn = await db.OpenConnectionAsync(ct);

            // Ownership check + (site_id, env) routing-scope resolution per resource:
            // every resourceId must be a UUID resolving to a cluster owned by this org.
            // env reads via to_jsonb so the query stays valid on deployments where the
            // cluster_mgmt env column (AB#2766) has not landed yet — absent → 'default'.
            var targets = new List<(Guid ResourceId, Guid? SiteId, string Env)>(req.ResourceIds.Count);
            foreach (var resourceId in req.ResourceIds)
            {
                if (!Guid.TryParse(resourceId, out var resourceGuid))
                {
                    return Results.Json(
                        new { error = "invalid-resource-id", message = $"Resource id '{resourceId}' is not a valid UUID." },
                        statusCode: StatusCodes.Status400BadRequest);
                }

                Guid? siteId;
                string env;
                await using var resolveCmd = new NpgsqlCommand("""
                    SELECT c.site_id, COALESCE(to_jsonb(c) ->> 'env', 'default') AS env
                    FROM cluster_mgmt.clusters c
                    WHERE c.cluster_id = @id AND c.org_id = @org_id
                    LIMIT 1
                    """, conn);
                resolveCmd.Parameters.Add(new NpgsqlParameter("@id", NpgsqlDbType.Uuid) { Value = resourceGuid });
                resolveCmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
                await using (var resolveReader = await resolveCmd.ExecuteReaderAsync(ct))
                {
                    if (!await resolveReader.ReadAsync(ct))
                    {
                        return Results.Json(
                            new { error = "resource-access-denied", message = $"Resource '{resourceId}' was not found or does not belong to your organisation." },
                            statusCode: StatusCodes.Status403Forbidden);
                    }
                    siteId = resolveReader.IsDBNull(0) ? null : resolveReader.GetGuid(0);
                    env    = JobEnvironments.Normalize(resolveReader.IsDBNull(1) ? null : resolveReader.GetString(1));
                }
                targets.Add((resourceGuid, siteId, env));
            }

            var idempotencyKey = string.IsNullOrWhiteSpace(req.IdempotencyKey) ? null : req.IdempotencyKey.Trim();

            Guid batchId;
            await using var tx = await conn.BeginTransactionAsync(ct);
            try
            {
                // Batch-level idempotency per contract §4.1: a duplicate
                // (org_id, idempotency_key) inserts nothing and the existing batch
                // is returned (200, not 409).
                await using (var cmd = new NpgsqlCommand("""
                    INSERT INTO core.job_batches
                        (org_id, created_by, operation, parameters, total_items, idempotency_key)
                    VALUES
                        (@org_id, @created_by, @operation, @parameters::jsonb, @total_items, @idempotency_key)
                    ON CONFLICT (org_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
                    RETURNING batch_id
                    """, conn, tx))
                {
                    cmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
                    cmd.Parameters.Add(new NpgsqlParameter("@created_by", NpgsqlDbType.Uuid) { Value = userId });
                    cmd.Parameters.Add(new NpgsqlParameter("@operation", NpgsqlDbType.Text) { Value = req.Operation });
                    cmd.Parameters.Add(new NpgsqlParameter("@parameters", NpgsqlDbType.Text)
                        { Value = parametersJson is null ? DBNull.Value : (object)parametersJson });
                    cmd.Parameters.Add(new NpgsqlParameter("@total_items", NpgsqlDbType.Integer)
                        { Value = req.ResourceIds.Count });
                    cmd.Parameters.Add(new NpgsqlParameter("@idempotency_key", NpgsqlDbType.Text)
                        { Value = (object?)idempotencyKey ?? DBNull.Value });
                    var scalar = await cmd.ExecuteScalarAsync(ct);

                    if (scalar is not Guid createdBatchId)
                    {
                        // Duplicate idempotency key — return the existing batch.
                        await tx.RollbackAsync(ct);
                        return await ExistingBatchResponseAsync(conn, orgId, idempotencyKey!, ct);
                    }
                    batchId = createdBatchId;
                }

                // One core.jobs row per resource — status 'queued', canonical dispatch
                // pipeline takes it from here (no batch-specific dispatch path).
                var timeoutAt = DateTimeOffset.UtcNow + DefaultJobTimeout;
                foreach (var (resourceGuid, siteId, env) in targets)
                {
                    var payloadJson = parametersJson is null
                        ? JsonSerializer.Serialize(new { resourceId = resourceGuid })
                        : $$"""{"resourceId":"{{resourceGuid}}","parameters":{{parametersJson}}}""";

                    Guid jobId;
                    await using (var jobCmd = new NpgsqlCommand("""
                        INSERT INTO core.jobs
                            (org_id, job_type, status, payload_json, created_by_user_id,
                             idempotency_key, site_id, env, timeout_at)
                        VALUES
                            (@org_id, @job_type, 'queued', @payload::jsonb, @created_by,
                             @idempotency_key, @site_id, @env, @timeout_at)
                        RETURNING job_id
                        """, conn, tx))
                    {
                        jobCmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
                        jobCmd.Parameters.Add(new NpgsqlParameter("@job_type", NpgsqlDbType.Text) { Value = req.Operation });
                        jobCmd.Parameters.Add(new NpgsqlParameter("@payload", NpgsqlDbType.Text) { Value = payloadJson });
                        jobCmd.Parameters.Add(new NpgsqlParameter("@created_by", NpgsqlDbType.Uuid) { Value = userId });
                        // Per-child dedupe key derived from the batch key (unique per org).
                        jobCmd.Parameters.Add(new NpgsqlParameter("@idempotency_key", NpgsqlDbType.Text)
                            { Value = idempotencyKey is null ? DBNull.Value : (object)$"{idempotencyKey}:{resourceGuid}" });
                        jobCmd.Parameters.Add(new NpgsqlParameter("@site_id", NpgsqlDbType.Uuid)
                            { Value = (object?)siteId ?? DBNull.Value });
                        jobCmd.Parameters.Add(new NpgsqlParameter("@env", NpgsqlDbType.Text) { Value = env });
                        jobCmd.Parameters.Add(new NpgsqlParameter("@timeout_at", NpgsqlDbType.TimestampTz) { Value = timeoutAt });
                        jobId = (Guid)(await jobCmd.ExecuteScalarAsync(ct))!;
                    }

                    await using var itemCmd = new NpgsqlCommand("""
                        INSERT INTO core.job_batch_items (batch_id, resource_id, job_id)
                        VALUES (@batch_id, @resource_id, @job_id)
                        """, conn, tx);
                    itemCmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                    itemCmd.Parameters.Add(new NpgsqlParameter("@resource_id", NpgsqlDbType.Text) { Value = resourceGuid.ToString() });
                    itemCmd.Parameters.Add(new NpgsqlParameter("@job_id", NpgsqlDbType.Uuid) { Value = jobId });
                    await itemCmd.ExecuteNonQueryAsync(ct);
                }

                await tx.CommitAsync(ct);
            }
            catch
            {
                await tx.RollbackAsync(ct);
                throw;
            }

            return Results.Accepted(
                $"/api/v1/jobs/batch/{batchId}",
                new JobBatchCreatedResponse(batchId.ToString(), BatchStatuses.Queued, req.ResourceIds.Count));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("jobs:write")))
        .WithSummary("Create a job batch — every item creates a core.jobs row entering the canonical dispatch pipeline. AB#4843.");

        // GET /api/v1/jobs/batch/{batchId} — header + aggregated status.
        jobs.MapGet("/batch/{batchId:guid}", async (
            Guid batchId,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            await using var conn = await db.OpenConnectionAsync(ct);

            string operation;
            int totalItems;
            DateTimeOffset createdAt, updatedAt;
            await using (var cmd = new NpgsqlCommand("""
                SELECT operation, total_items, created_at, updated_at
                FROM core.job_batches
                WHERE batch_id = @batch_id AND org_id = @org_id
                """, conn))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                cmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                    return Results.NotFound(new { error = "batch-not-found", batchId });
                operation  = reader.GetString(0);
                totalItems = reader.GetInt32(1);
                createdAt  = reader.GetFieldValue<DateTimeOffset>(2);
                updatedAt  = reader.GetFieldValue<DateTimeOffset>(3);
            }

            var counts = await LoadChildCountsAsync(conn, batchId, ct);

            return Results.Ok(new
            {
                batchId,
                operation,
                status     = BatchStatusAggregator.Compute(counts),
                totalItems,
                queued     = counts.Queued,
                dispatched = counts.Dispatched,
                running    = counts.Running,
                succeeded  = counts.Succeeded,
                failed     = counts.Failed,
                timedOut   = counts.TimedOut,
                cancelled  = counts.Cancelled,
                createdAt,
                updatedAt,
            });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("jobs:read")))
        .WithSummary("Get a job batch header with status aggregated over its child jobs. AB#4843.");

        // GET /api/v1/jobs/batch/{batchId}/items — paginated items with child job status.
        jobs.MapGet("/batch/{batchId:guid}/items", async (
            Guid batchId,
            NpgsqlDataSource db,
            HttpContext ctx,
            int page      = 1,
            int pageSize  = 50,
            CancellationToken ct = default) =>
        {
            var orgIdClaim = ctx.User.FindFirstValue("org_id");
            if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out var orgId))
            {
                return Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            }

            page     = Math.Max(1, page);
            pageSize = Math.Clamp(pageSize, 1, 500);

            await using var conn = await db.OpenConnectionAsync(ct);

            // Ownership check.
            await using (var ownCmd = new NpgsqlCommand(
                "SELECT 1 FROM core.job_batches WHERE batch_id = @batch_id AND org_id = @org_id", conn))
            {
                ownCmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                ownCmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
                if (await ownCmd.ExecuteScalarAsync(ct) is null)
                    return Results.NotFound(new { error = "batch-not-found", batchId });
            }

            int totalItems;
            await using (var countCmd = new NpgsqlCommand(
                "SELECT COUNT(*)::int FROM core.job_batch_items WHERE batch_id = @batch_id", conn))
            {
                countCmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                totalItems = (int)(await countCmd.ExecuteScalarAsync(ct) ?? 0);
            }

            var items = new List<object>();
            await using (var cmd = new NpgsqlCommand("""
                SELECT i.item_id, i.resource_id, i.job_id,
                       COALESCE(j.status, i.status) AS status,
                       j.started_at, j.completed_at, COALESCE(j.error_message, i.error_message)
                FROM core.job_batch_items i
                LEFT JOIN core.jobs j ON j.job_id = i.job_id
                WHERE i.batch_id = @batch_id
                ORDER BY i.item_id
                LIMIT @limit OFFSET @offset
                """, conn))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                cmd.Parameters.Add(new NpgsqlParameter("@limit", NpgsqlDbType.Integer) { Value = pageSize });
                cmd.Parameters.Add(new NpgsqlParameter("@offset", NpgsqlDbType.Integer) { Value = (page - 1) * pageSize });
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    items.Add(new
                    {
                        itemId       = reader.GetGuid(0),
                        resourceId   = reader.GetString(1),
                        jobId        = reader.IsDBNull(2) ? (Guid?)null : reader.GetGuid(2),
                        status       = reader.GetString(3),
                        startedAt    = reader.IsDBNull(4) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(4),
                        completedAt  = reader.IsDBNull(5) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(5),
                        errorMessage = reader.IsDBNull(6) ? null : reader.GetString(6),
                    });
                }
            }

            return Results.Ok(new
            {
                items,
                pagination = new
                {
                    page,
                    pageSize,
                    totalItems,
                    totalPages = (int)Math.Ceiling((double)totalItems / pageSize),
                },
            });
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("jobs:read")))
        .WithSummary("List batch items with each item's child jobId and canonical job status. AB#4843.");

        return app;
    }

    private static async Task<IResult> ExistingBatchResponseAsync(
        NpgsqlConnection conn, Guid orgId, string idempotencyKey, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            SELECT batch_id, status, total_items
            FROM core.job_batches
            WHERE org_id = @org_id AND idempotency_key = @idempotency_key
            """, conn);
        cmd.Parameters.Add(new NpgsqlParameter("@org_id", NpgsqlDbType.Uuid) { Value = orgId });
        cmd.Parameters.Add(new NpgsqlParameter("@idempotency_key", NpgsqlDbType.Text) { Value = idempotencyKey });
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            // Extremely unlikely (row deleted between conflict and read) — surface as 500.
            return Results.Json(new { error = "idempotency-lookup-failed" }, statusCode: StatusCodes.Status500InternalServerError);
        }
        return Results.Ok(new JobBatchCreatedResponse(
            reader.GetGuid(0).ToString(), reader.GetString(1), reader.GetInt32(2)));
    }

    private static async Task<BatchChildCounts> LoadChildCountsAsync(
        NpgsqlConnection conn, Guid batchId, CancellationToken ct)
    {
        var rows = new List<(string Status, int Count)>();
        await using var cmd = new NpgsqlCommand("""
            SELECT COALESCE(j.status, i.status) AS status, COUNT(*)::int
            FROM core.job_batch_items i
            LEFT JOIN core.jobs j ON j.job_id = i.job_id
            WHERE i.batch_id = @batch_id
            GROUP BY COALESCE(j.status, i.status)
            """, conn);
        cmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            rows.Add((reader.GetString(0), reader.GetInt32(1)));
        return BatchStatusAggregator.FromStatusCounts(rows);
    }
}
