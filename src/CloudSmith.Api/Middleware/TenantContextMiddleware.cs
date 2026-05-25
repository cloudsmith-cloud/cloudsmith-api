// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Serilog.Context;
using System.Security.Claims;

namespace CloudSmith.Api.Endpoints;

public sealed class TenantContextMiddleware
{
    private readonly RequestDelegate _next;

    public TenantContextMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        // Extract org_id and user_id from JWT claims; populate HttpContext.Items for downstream use
        if (ctx.User?.Identity?.IsAuthenticated == true)
        {
            if (Guid.TryParse(ctx.User.FindFirstValue("org_id"), out var orgId))
            {
                ctx.Items["OrgId"] = orgId;
                using (LogContext.PushProperty("TenantId", orgId))
                {
                    if (Guid.TryParse(ctx.User.FindFirstValue("sub") ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
                        ctx.Items["UserId"] = userId;

                    await _next(ctx);
                    return;
                }
            }
        }
        await _next(ctx);
    }
}
