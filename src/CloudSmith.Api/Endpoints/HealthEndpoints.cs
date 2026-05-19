// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.Text.Json;

namespace CloudSmith.Api.Endpoints;

public static class HealthEndpoints
{
    public static IEndpointRouteBuilder MapHealthEndpoints(this IEndpointRouteBuilder app)
    {
        // /health/live — always 200; never includes slow checks (liveness probe)
        app.MapGet("/health/live", () => Results.Ok(new { status = "healthy" }))
           .WithTags("Health")
           .ExcludeFromDescription();

        // /health/ready — 200 only when DB is up; 503 with structured body on failure
        app.MapHealthChecks("/health/ready", new HealthCheckOptions
        {
            Predicate = check => check.Tags.Contains("ready"),
            ResponseWriter = WriteHealthResponse,
            ResultStatusCodes =
            {
                [HealthStatus.Healthy]   = StatusCodes.Status200OK,
                [HealthStatus.Degraded]  = StatusCodes.Status200OK,
                [HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable,
            }
        });

        // /health/startup — used by Kubernetes startup probe; same as ready
        app.MapHealthChecks("/health/startup", new HealthCheckOptions
        {
            Predicate = check => check.Tags.Contains("ready"),
            ResponseWriter = WriteHealthResponse,
            ResultStatusCodes =
            {
                [HealthStatus.Healthy]   = StatusCodes.Status200OK,
                [HealthStatus.Degraded]  = StatusCodes.Status200OK,
                [HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable,
            }
        });

        return app;
    }

    private static Task WriteHealthResponse(HttpContext ctx, HealthReport report)
    {
        ctx.Response.ContentType = "application/json";
        var result = new
        {
            status = report.Status.ToString().ToLowerInvariant(),
            checks = report.Entries.Select(e => new
            {
                name        = e.Key,
                status      = e.Value.Status.ToString().ToLowerInvariant(),
                description = e.Value.Description,
            })
        };
        return ctx.Response.WriteAsync(JsonSerializer.Serialize(result));
    }
}
