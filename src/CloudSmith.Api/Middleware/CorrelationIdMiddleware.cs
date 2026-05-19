// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Serilog.Context;

namespace CloudSmith.Api.Endpoints;

public sealed class CorrelationIdMiddleware
{
    private readonly RequestDelegate _next;

    public CorrelationIdMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        var correlationId = ctx.Request.Headers["X-Correlation-Id"].FirstOrDefault()
            ?? Guid.NewGuid().ToString();

        ctx.Response.Headers["X-Correlation-Id"] = correlationId;
        ctx.Items["CorrelationId"] = correlationId;

        using (LogContext.PushProperty("CorrelationId", correlationId))
            await _next(ctx);
    }
}
