// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authorization;

namespace CloudSmith.Api.Authorization;

public static class AuthorizationExtensions
{
    public static IServiceCollection AddCloudSmithAuthorization(this IServiceCollection services)
    {
        services.AddAuthentication();
        services.AddAuthorization();
        // PermissionAuthorizationHandler depends on ICloudSmithAuthorizationService (Scoped),
        // so the handler itself must be Scoped — not Singleton.
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
        return services;
    }

    public static Guid? GetOrgId(this HttpContext ctx)
    {
        var val = ctx.Items["OrgId"];
        return val is Guid g ? g : null;
    }

    public static Guid? GetUserId(this HttpContext ctx)
    {
        var val = ctx.Items["UserId"];
        return val is Guid g ? g : null;
    }

    public static Guid? GetSiteId(this HttpContext ctx)
    {
        var val = ctx.Items["SiteId"];
        return val is Guid g ? g : null;
    }

    public static Guid? GetClusterId(this HttpContext ctx)
    {
        var val = ctx.Items["ClusterId"];
        return val is Guid g ? g : null;
    }
}
