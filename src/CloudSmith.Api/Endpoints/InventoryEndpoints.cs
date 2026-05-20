// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Inventory.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace CloudSmith.Api.Endpoints;

public static class InventoryEndpoints
{
    public static IEndpointRouteBuilder MapInventoryEndpoints(this IEndpointRouteBuilder app)
    {
        var vms = app.MapGroup("/api/v1/vms").RequireAuthorization();

        vms.MapGet("/", async (HttpContext ctx, IVirtualMachineService svc,
            Guid? clusterId, CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            if (clusterId.HasValue)
                return Results.Ok(await svc.ListByClusterAsync(clusterId.Value, orgId, ct));
            return Results.BadRequest(new { error = "clusterId query parameter is required" });
        });

        vms.MapGet("/{id:guid}", async (Guid id, HttpContext ctx, IVirtualMachineService svc, CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            var vm = await svc.GetVmAsync(id, orgId, ct);
            return vm is null ? Results.NotFound() : Results.Ok(vm);
        });

        var workloads = app.MapGroup("/api/v1/workloads").RequireAuthorization();

        workloads.MapGet("/", async (HttpContext ctx, IWorkloadService svc, CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            return Results.Ok(await svc.ListWorkloadsAsync(orgId, ct));
        });

        workloads.MapGet("/{id:guid}", async (Guid id, HttpContext ctx, IWorkloadService svc, CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId)) return Results.Unauthorized();
            var workload = await svc.GetWorkloadAsync(id, orgId, ct);
            return workload is null ? Results.NotFound() : Results.Ok(workload);
        });

        return app;
    }

    private static bool TryGetOrgId(HttpContext ctx, out Guid orgId)
    {
        if (ctx.Items["OrgId"] is Guid id) { orgId = id; return true; }
        orgId = default;
        return false;
    }
}
