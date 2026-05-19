// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Sdk.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace CloudSmith.Api.Authorization;

public sealed class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    private readonly ICloudSmithAuthorizationService _authz;

    public PermissionAuthorizationHandler(ICloudSmithAuthorizationService authz)
    {
        _authz = authz;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        if (context.Resource is not HttpContext http) return;

        var orgId  = http.GetOrgId();
        var userId = http.GetUserId();
        if (orgId == null || userId == null) return;

        var ctx    = new AuthorizationContext(userId.Value, orgId.Value, http.GetSiteId(), http.GetClusterId());
        var allowed = await _authz.HasPermissionAsync(ctx, requirement.Permission);

        if (allowed)
            context.Succeed(requirement);
        // 403 is returned by ASP.NET Core when no handler succeeds
    }
}
