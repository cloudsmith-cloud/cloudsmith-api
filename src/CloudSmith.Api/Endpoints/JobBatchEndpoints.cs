// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using System.Text.Json;
using CloudSmith.Api.Authorization;
using CloudSmith.Api.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Bulk job batching endpoint — AB#1931.
/// POST /api/v1/jobs/batch — creates a batch record and enqueues each resourceId as a sub-task.
/// Returns { jobId, status: "queued" } immediately.
///
/// Processing model: a background Task picks up queued batches and processes sub-tasks sequentially.
/// In Phase IV this is an in-process sequential processor; Phase V will replace with a durable worker.
/// </summary>
public static class JobBatchEndpoints
{
    public sealed record JobBatchRequest(
        string Operation,
        IReadOnlyList<string> ResourceIds,
        JsonElement? Parameters);

    public sealed record JobBatchResponse(
        string JobId,
        string Status);

    public static IEndpointRouteBuilder MapJobBatchEndpoints(this IEndpointRouteBuilder app)
    {
        var jobs = app.MapGroup("/api/v1/jobs").WithTags("Jobs");

        // POST /api/v1/jobs/batch
        jobs.MapPost("/batch", async (
            JobBatchRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            IJobBatchProcessor processor,
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

            var parametersJson = req.Parameters is { ValueKind: not JsonValueKind.Undefined and not JsonValueKind.Null }
                ? req.Parameters.Value.GetRawText()
                : null;

            Guid batchId;
            await using var conn = await db.OpenConnectionAsync(ct);
            await using var tx = await conn.BeginTransactionAsync(ct);

            try
            {
                // Insert batch header.
                await using (var cmd = new NpgsqlCommand("""
                    INSERT INTO core.job_batches
                        (org_id, created_by, operation, parameters, total_items)
                    VALUES
                        (@org_id, @created_by, @operation, @parameters::jsonb, @total_items)
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
                    var scalar = await cmd.ExecuteScalarAsync(ct);
                    batchId = (Guid)scalar!;
                }

                // Insert sub-task items.
                foreach (var resourceId in req.ResourceIds)
                {
                    await using var itemCmd = new NpgsqlCommand("""
                        INSERT INTO core.job_batch_items (batch_id, resource_id)
                        VALUES (@batch_id, @resource_id)
                        """, conn, tx);
                    itemCmd.Parameters.Add(new NpgsqlParameter("@batch_id", NpgsqlDbType.Uuid) { Value = batchId });
                    itemCmd.Parameters.Add(new NpgsqlParameter("@resource_id", NpgsqlDbType.Text) { Value = resourceId });
                    await itemCmd.ExecuteNonQueryAsync(ct);
                }

                await tx.CommitAsync(ct);
            }
            catch
            {
                await tx.RollbackAsync(ct);
                throw;
            }

            // Enqueue processing — fire-and-forget via the in-process processor.
            _ = processor.ProcessBatchAsync(batchId, CancellationToken.None);

            return Results.Ok(new JobBatchResponse(batchId.ToString(), "queued"));
        })
        .RequireAuthorization()
        .WithSummary("Create a bulk job batch — enqueues each resourceId as a sub-task. Returns jobId immediately. AB#1931.");

        return app;
    }
}
