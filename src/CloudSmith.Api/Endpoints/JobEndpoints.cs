// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Hubs;
using CloudSmith.Core.Jobs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.SignalR;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Job status and log endpoints.
///
/// GET  /api/v1/jobs/{jobId}       — get job status (AB#1429)
/// GET  /api/v1/jobs/{jobId}/log   — get paginated job log (AB#1429)
///
/// SignalR: clients receive JobUpdated events on the PlatformHub job group
/// whenever a job transitions status. Streaming is handled by the individual
/// module workers that call IJobService.UpdateJobStatusAsync and then push
/// via IHubContext{PlatformHub}.
///
/// AB#1429
/// </summary>
public static class JobEndpoints
{
    public static IEndpointRouteBuilder MapJobEndpoints(this IEndpointRouteBuilder app)
    {
        var jobs = app.MapGroup("/api/v1/jobs").RequireAuthorization();

        // GET /api/v1/jobs/{jobId}
        jobs.MapGet("/{jobId:guid}", async (
            Guid jobId,
            HttpContext ctx,
            IJobService svc,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            var job = await svc.GetJobAsync(jobId, orgId, ct);
            if (job is null) return Results.NotFound(new { error = "job-not-found" });

            return Results.Ok(new
            {
                jobId         = job.JobId,
                orgId         = job.OrgId,
                operation     = job.JobType,
                status        = MapStatus(job.Status),
                runnerId      = job.RunnerId,
                moduleId      = job.ModuleId,
                result        = job.ResultJson,
                errorCode     = job.ErrorCode,
                errorMessage  = job.ErrorMessage,
                createdAt     = job.CreatedAt,
                startedAt     = job.StartedAt,
                completedAt   = job.CompletedAt,
                logUrl        = $"/api/v1/jobs/{job.JobId}/log",
            });
        })
        .WithTags("Jobs")
        .WithSummary("Get job status by ID.");

        // GET /api/v1/jobs/{jobId}/log?severity=Info&page=1&pageSize=100
        jobs.MapGet("/{jobId:guid}/log", async (
            Guid jobId,
            HttpContext ctx,
            IJobService svc,
            string? severity,
            int page     = 1,
            int pageSize = 100,
            CancellationToken ct = default) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();

            // Verify job exists and belongs to this org before returning log
            var job = await svc.GetJobAsync(jobId, orgId, ct);
            if (job is null) return Results.NotFound(new { error = "job-not-found" });

            pageSize = Math.Clamp(pageSize, 1, 500);
            page     = Math.Max(1, page);

            var (items, total) = await svc.GetJobLogAsync(jobId, orgId, severity, page, pageSize, ct);
            return Results.Ok(new
            {
                items = items.Select(e => new
                {
                    logId    = e.LogId,
                    jobId    = e.JobId,
                    severity = e.Severity,
                    message  = e.Message,
                    source   = e.Source,
                    loggedAt = e.LoggedAt,
                }),
                pagination = new
                {
                    page,
                    pageSize,
                    totalItems = total,
                    totalPages = (int)Math.Ceiling((double)total / pageSize),
                },
            });
        })
        .WithTags("Jobs")
        .WithSummary("Get paginated log output for a job.");

        return app;
    }

    /// <summary>
    /// Maps internal DB status values to the API contract status strings (AB#1429 spec).
    /// DB uses snake_case: queued, dispatched, running, succeeded, failed, cancelled, timed_out.
    /// API contract uses PascalCase: Queued, Dispatched, Running, Completed, Failed, Cancelled.
    /// </summary>
    private static string MapStatus(string dbStatus) => dbStatus switch
    {
        "queued"    => "Queued",
        "dispatched"=> "Dispatched",
        "running"   => "Running",
        "succeeded" => "Completed",
        "failed"    => "Failed",
        "cancelled" => "Cancelled",
        "timed_out" => "Failed",
        _           => dbStatus,
    };

    private static bool TryGetOrgId(HttpContext ctx, out Guid orgId)
    {
        if (ctx.Items["OrgId"] is Guid id) { orgId = id; return true; }
        orgId = default;
        return false;
    }
}
