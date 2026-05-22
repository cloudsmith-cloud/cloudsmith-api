// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Authorization;
using CloudSmith.Api.Endpoints;
using Microsoft.AspNetCore.HttpOverrides;
using CloudSmith.ClusterMgmt;
using CloudSmith.ClusterMgmt.Services;
using CloudSmith.Core.Hosting;
using CloudSmith.Identity;
using CloudSmith.Inventory;
using CloudSmith.Inventory.Services;
using CloudSmith.Monitoring;
using FluentMigrator.Runner;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Scalar.AspNetCore;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Serilog structured logging — correlation_id + tenant_id enriched per request
builder.Host.UseSerilog((ctx, cfg) => cfg
    .ReadFrom.Configuration(ctx.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("service", "cloudsmith-api")
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {CorrelationId} {TenantId} {Message:lj}{NewLine}{Exception}"));

// OpenTelemetry tracing → otel-collector at 4317
builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("cloudsmith-api"))
    .WithTracing(t => t
        .AddAspNetCoreInstrumentation()
        .AddOtlpExporter(o => o.Endpoint = new Uri(
            builder.Configuration["OpenTelemetry:Endpoint"] ?? "http://localhost:4317")));

// Platform kernel (migrations + RBAC + Config + health + NpgsqlDataSource)
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? builder.Configuration.GetConnectionString("CloudSmith")
    ?? throw new InvalidOperationException("CS-CORE-ERR-001: Required configuration 'ConnectionStrings:Default' is missing");
builder.Services.AddCloudSmithCore(connectionString);

// Identity — Cookie + OIDC (browser) + JWT Bearer (runners/API-to-API)
builder.Services.AddCloudSmithIdentity(builder.Configuration);

// Cluster management — register services directly; FM migrations run in isolated scope below
builder.Services.AddScoped<IClusterService, PostgresClusterService>();
builder.Services.AddScoped<INodeService, PostgresNodeService>();

// Inventory — register services directly; FM migrations run in isolated scope below
builder.Services.AddScoped<IVirtualMachineService, PostgresVirtualMachineService>();
builder.Services.AddScoped<IWorkloadService, PostgresWorkloadService>();

// Monitoring — health probing, alert evaluation, OTel metrics, HealthMonitorWorker
builder.Services.AddCloudSmithMonitoring(opts =>
{
    builder.Configuration.GetSection("Monitoring").Bind(opts);
});

// API-layer services
builder.Services.AddCloudSmithAuthorization();
builder.Services.AddOpenApi();

var app = builder.Build();

// Run all module migrations on startup using isolated scopes to avoid FM runner conflicts
app.Services.MigrateCloudSmithDatabase();
MigrateAllDatabases(connectionString);

// Trust X-Forwarded-* headers from nginx reverse proxy.
// KnownNetworks/KnownProxies default to loopback only; the portal nginx runs in a
// separate container (non-loopback IP), so clear them to trust the forwarded headers
// (incl. X-Forwarded-Host) it sets — required for correct OIDC redirect_uri and
// same-origin auth cookie behind the portal reverse proxy on ACA.
var forwardedHeadersOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
};
forwardedHeadersOptions.KnownNetworks.Clear();
forwardedHeadersOptions.KnownProxies.Clear();
app.UseForwardedHeaders(forwardedHeadersOptions);

// Middleware (auth must come after routing, before endpoints)
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseCloudSmithIdentity();
app.UseMiddleware<TenantContextMiddleware>();

// Prometheus metrics scraping endpoint
app.UseOpenTelemetryPrometheusScrapingEndpoint();

// Health endpoints per health-check-contract.md
app.MapHealthEndpoints();

// Auth endpoints (login / logout / me)
app.MapAuthEndpoints();

// API endpoints
app.MapConfigEndpoints();
app.MapClusterEndpoints();
app.MapInventoryEndpoints();

// OpenAPI / Scalar docs
app.MapOpenApi();
app.MapScalarApiReference();

app.Run();

// Runs FluentMigrator for cluster-mgmt and inventory in separate isolated scopes.
// Each module's AddXxx() registers its own FM runner; calling them both on the main
// service collection would cause the last registration to overwrite the first.
// Isolated scopes ensure each assembly's migrations run against the correct runner.
static void MigrateAllDatabases(string connectionString)
{
    RunMigrations(connectionString, typeof(CloudSmith.ClusterMgmt.ClusterMgmtExtensions).Assembly);
    RunMigrations(connectionString, typeof(CloudSmith.Inventory.InventoryExtensions).Assembly);
}

static void RunMigrations(string connectionString, System.Reflection.Assembly migrationsAssembly)
{
    // Standalone provider intentionally isolated from the app container so each module's
    // FluentMigrator runner resolves against the correct migrations assembly.
#pragma warning disable ASP0000
    var services = new ServiceCollection()
        .AddFluentMigratorCore()
        .ConfigureRunner(rb => rb
            .AddPostgres()
            .WithGlobalConnectionString(connectionString)
            .ScanIn(migrationsAssembly).For.Migrations())
        .AddLogging(lb => lb.AddFluentMigratorConsole())
        .BuildServiceProvider();
#pragma warning restore ASP0000

    using var scope = services.CreateScope();
    scope.ServiceProvider.GetRequiredService<IMigrationRunner>().MigrateUp();
}

// Expose for integration testing
public partial class Program { }
