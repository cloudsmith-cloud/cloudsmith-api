// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using CloudSmith.Api.Authorization;
using CloudSmith.Sdk.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Permissions introspection endpoint.
///
/// GET /api/v1/auth/me/permissions — returns the calling user's effective permission set
/// for the authenticated organisation context.
///
/// Response: { permissions: ["cluster:read", "cluster:write", ...] }
///
/// AB#1422
/// </summary>
public static class PermissionsEndpoints
{
    public static IEndpointRouteBuilder MapPermissionsEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/auth/me/permissions",
            async (
                HttpContext ctx,
                ICloudSmithAuthorizationService authSvc,
                CancellationToken ct) =>
            {
                if (!ctx.User.Identity?.IsAuthenticated ?? true)
                    return Results.Unauthorized();

                var orgIdStr  = ctx.User.FindFirstValue("org_id");
                var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier)
                             ?? ctx.User.FindFirstValue("sub");

                if (string.IsNullOrEmpty(orgIdStr) || string.IsNullOrEmpty(userIdStr))
                    return Results.Json(
                        new { error = "missing-context", message = "org_id or user identity claim not present" },
                        statusCode: StatusCodes.Status400BadRequest);

                var permissions = await authSvc.GetEffectivePermissionsAsync(orgIdStr, userIdStr, ct);
                return Results.Ok(new { permissions });
            })
        .RequireAuthorization()
        .WithTags("Auth")
        .WithSummary("Returns the calling user's effective permission set for their authenticated org.");

        return app;
    }
}
