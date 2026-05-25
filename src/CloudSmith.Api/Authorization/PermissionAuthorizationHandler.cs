// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Sdk.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace CloudSmith.Api.Authorization;

public sealed class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    private readonly ICloudSmithAuthorizationService _authz;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public PermissionAuthorizationHandler(
        ICloudSmithAuthorizationService authz,
        IHttpContextAccessor httpContextAccessor)
    {
        _authz = authz;
        _httpContextAccessor = httpContextAccessor;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        // context.Resource is HttpContext when called from endpoint routing (minimal APIs).
        // Fall back to IHttpContextAccessor for cases where the resource is set differently
        // (e.g., policy-based auth called outside endpoint routing context).
        var http = context.Resource as HttpContext
                   ?? _httpContextAccessor.HttpContext;

        if (http is null) return;

        var orgId  = http.GetOrgId();
        var userId = http.GetUserId();
        if (orgId == null || userId == null) return;

        var ctx     = new AuthorizationContext(http.GetSiteId()?.ToString(), http.GetClusterId()?.ToString());
        var allowed = await _authz.AuthorizeAsync(
            orgId.Value.ToString(), userId.Value.ToString(), requirement.Permission, ctx, http.RequestAborted);

        if (allowed)
            context.Succeed(requirement);
        // 403 is returned by ASP.NET Core when no handler succeeds
    }
}
