// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Asp.Versioning;
using CloudSmith.Api.Authorization;
using CloudSmith.Api.Endpoints;
using CloudSmith.Api.Hubs;
using CloudSmith.Api.Relay;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using CloudSmith.ClusterMgmt;
using CloudSmith.ClusterMgmt.Services;
using CloudSmith.Core.Hosting;
using CloudSmith.Identity;
using CloudSmith.Inventory;
using CloudSmith.Inventory.Services;
using CloudSmith.Monitoring;
using FluentMigrator.Runner;
using Microsoft.Extensions.DependencyInjection;
using Azure.Monitor.OpenTelemetry.AspNetCore;
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

// OpenTelemetry tracing — OTLP for local docker-compose; Azure Monitor for PaaS
var otelBuilder = builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("cloudsmith-api"))
    .WithTracing(t => t
        .AddAspNetCoreInstrumentation()
        .AddOtlpExporter(o => o.Endpoint = new Uri(
            builder.Configuration["OpenTelemetry:Endpoint"] ?? "http://localhost:4317")));
var aiConnString = builder.Configuration["ApplicationInsights:ConnectionString"];
if (!string.IsNullOrEmpty(aiConnString))
    otelBuilder.UseAzureMonitor(o => o.ConnectionString = aiConnString);

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

// SignalR — PlatformHub for real-time portal and runner events (AB#1436).
// JWT auth is handled by the ASP.NET Core auth middleware (same pipeline as REST);
// SignalR also supports query-string token for browser WebSocket connections.
builder.Services.AddSignalR(opts =>
{
    opts.EnableDetailedErrors = builder.Environment.IsDevelopment();
    opts.HandshakeTimeout    = TimeSpan.FromSeconds(15);
    opts.KeepAliveInterval   = TimeSpan.FromSeconds(15);
    opts.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
});

// API versioning — api-version header + deprecated-version warning (AB#1439).
// Version format: Major.Minor. Default = 1.0. Deprecated versions return a
// "api-deprecated-version" response header warning callers to upgrade.
builder.Services.AddApiVersioning(opts =>
{
    opts.DefaultApiVersion               = new ApiVersion(1, 0);
    opts.AssumeDefaultVersionWhenUnspecified = true;
    opts.ApiVersionReader               = new HeaderApiVersionReader("api-version");
    opts.ReportApiVersions              = true; // emits "api-supported-versions" + "api-deprecated-versions" headers
});

// Rate limiting — fixed-window per-IP per minute. Protects all API endpoints
// from abuse while still allowing normal portal + runner traffic (AB#1437).
// Limits: 120 requests/minute per IP. Auth endpoints have a stricter 20/minute limit.
builder.Services.AddRateLimiter(opts =>
{
    opts.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Default policy: 120 req/min per IP.
    opts.AddPolicy("default-limit", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit          = 120,
                Window               = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit           = 0,
            }));

    // Auth policy: 20 req/min per IP — prevents password spray.
    opts.AddPolicy("auth-limit", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit          = 20,
                Window               = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit           = 0,
            }));
});

// Relay WebSocket hub — in-memory registry of connected relay sockets (AB#1679)
builder.Services.AddSingleton<IConnectedRelayRegistry, ConnectedRelayRegistry>();

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

// WebSocket support — must be registered before the endpoint middleware so that
// the /api/v1/relays/{id}/connect hub can accept WebSocket upgrade requests (AB#1679).
app.UseWebSockets(new WebSocketOptions
{
    KeepAliveInterval = TimeSpan.FromSeconds(60),
});

// Rate limiting — must come before routing so the middleware fires on all matched routes.
app.UseRateLimiter();

// Middleware (auth must come after routing, before endpoints)
app.UseMiddleware<CorrelationIdMiddleware>();
// ADR-047 — block all non-allowlisted API traffic until first-run setup is complete.
// Runs before authentication so the setup wizard + local login work with no IdP.
app.UseMiddleware<SetupGateMiddleware>();
// UseAuthentication + UseAuthorization — must run before TenantContextMiddleware so
// that the identity is resolved first, but TenantContextMiddleware must run BEFORE
// UseAuthorization so that ctx.Items["OrgId"/"UserId"] are populated when
// PermissionAuthorizationHandler fires during endpoint authorization evaluation.
app.UseAuthentication();
app.UseMiddleware<TenantContextMiddleware>();
// UseAuthorization fires permission checks against already-populated ctx.Items.
app.UseAuthorization();

// Prometheus metrics scraping endpoint
app.UseOpenTelemetryPrometheusScrapingEndpoint();

// Health endpoints per health-check-contract.md
app.MapHealthEndpoints();

// Auth endpoints (login / logout / me)
app.MapAuthEndpoints();

// ADR-047 first-run setup + local login endpoints (anonymous)
app.MapSetupEndpoints();

// API endpoints
app.MapConfigEndpoints();
app.MapClusterEndpoints();
app.MapInventoryEndpoints();
app.MapPlatformEndpoints();   // AB#1640-1642 Modules (Platform Management group)
app.MapIdentityProviderEndpoints();   // AB#1643-1647 Identity Providers CRUD
app.MapUsersEndpoints();              // AB#1648-1649 Users + invite
app.MapAuditEndpoints();              // AB#1651 Audit log query
app.MapSitesEndpoints();              // AB#1652 Sites CRUD
app.MapSecretsEndpoints();            // AB#1653 Secrets refs CRUD
app.MapRelayEndpoints();              // AB#1670 Relay bridge — enrollment, clusters POST, inventory ingest, health probe

// SignalR PlatformHub — real-time events for portal and runners (AB#1436).
// Requires JWT Bearer or cookie auth (handled by ASP.NET Core middleware).
// Browser WebSocket auth: pass access_token query param (SignalR convention).
app.MapHub<PlatformHub>("/hubs/platform");

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
