// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Asp.Versioning;
using CloudSmith.Api;
using CloudSmith.Api.Authorization;
using CloudSmith.Api.Endpoints;
using CloudSmith.Api.Hubs;
using CloudSmith.Api.Relay;
using CloudSmith.Api.Services;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using CloudSmith.ClusterMgmt;
using CloudSmith.ClusterMgmt.Services;
using CloudSmith.Core.Hosting;
using CloudSmith.Identity;
using CloudSmith.Identity.Groups;
using CloudSmith.Identity.Users;
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

// AB#1601 — Deployment mode controls which OTel exporter is wired.
// CLOUDSMITH_DEPLOYMENT_MODE=PaaS → Azure Monitor; anything else → OTLP.
var deploymentMode = Enum.TryParse<DeploymentMode>(
    Environment.GetEnvironmentVariable("CLOUDSMITH_DEPLOYMENT_MODE"),
    ignoreCase: true,
    out var parsedMode)
    ? parsedMode
    : DeploymentMode.Standalone;

// Serilog structured logging — correlation_id + tenant_id enriched per request
builder.Host.UseSerilog((ctx, cfg) => cfg
    .ReadFrom.Configuration(ctx.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("service", "cloudsmith-api")
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {CorrelationId} {TenantId} {Message:lj}{NewLine}{Exception}"));

// OpenTelemetry tracing — exporter selected by DeploymentMode (AB#1601).
// Standalone: OTLP to local otel-collector.
// PaaS: Azure Monitor / Application Insights — connection string from
//       ApplicationInsights:ConnectionString config (populated at deploy time by
//       the platform secrets layer, key "appinsights_connection_string").
var otelBuilder = builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("cloudsmith-api"))
    .WithTracing(t => t.AddAspNetCoreInstrumentation());

if (deploymentMode == DeploymentMode.PaaS)
{
    var aiConnString = builder.Configuration["ApplicationInsights:ConnectionString"];
    otelBuilder.UseAzureMonitor(o =>
    {
        if (!string.IsNullOrEmpty(aiConnString))
            o.ConnectionString = aiConnString;
    });
}
else
{
    otelBuilder.WithTracing(t => t.AddOtlpExporter(o =>
        o.Endpoint = new Uri(builder.Configuration["OpenTelemetry:Endpoint"] ?? "http://localhost:4317")));
}

// Platform kernel (migrations + RBAC + Config + health + NpgsqlDataSource)
// AB#1600 — PaaS mode: ConnectionStrings:Default may be set to just the password (KV secret ref)
// when the full connection string is assembled from individual env vars. Detect this pattern
// and build a proper Npgsql connection string if the value doesn't look like a full conn string.
static string ResolveConnectionString(Microsoft.Extensions.Configuration.IConfiguration cfg)
{
    var raw = cfg.GetConnectionString("Default") ?? cfg.GetConnectionString("CloudSmith");
    if (raw is null)
        throw new InvalidOperationException("CS-CORE-ERR-001: Required configuration 'ConnectionStrings:Default' is missing");

    // If the value looks like a full Npgsql connection string (contains Host= or ;), use as-is.
    if (raw.Contains('=') || raw.Contains(';'))
        return raw;

    // Otherwise treat raw as just the password and assemble from separate env vars.
    // This happens in PaaS mode where ConnectionStrings__Default = KV pg-password secret.
    var host     = cfg["ConnectionStrings:DefaultHost"]     ?? "localhost";
    var database = cfg["ConnectionStrings:DefaultDatabase"] ?? "cloudsmith";
    var user     = cfg["ConnectionStrings:DefaultUser"]     ?? "cloudsmith";
    // Use SSL=Prefer so pgbouncer (localhost, no SSL) and direct PG (SSL enforced) both work.
    // pgbouncer listens on localhost without SSL; Azure PG Flexible requires SSL but
    // when pgbouncer is the host we connect to localhost. Prefer falls back to plain when SSL fails.
    var sslMode  = host == "localhost" ? "Disable" : "Require";
    return $"Host={host};Database={database};Username={user};Password={raw};SSL Mode={sslMode};Trust Server Certificate=true";
}
var connectionString = ResolveConnectionString(builder.Configuration);
builder.Services.AddCloudSmithCore(connectionString);

// Identity — Cookie + OIDC (browser) + JWT Bearer (runners/API-to-API)
builder.Services.AddCloudSmithIdentity(builder.Configuration);
// User and Group services — registered separately so they can resolve NpgsqlDataSource from DI.
builder.Services.AddScoped<CloudSmith.Identity.Users.IUserService, CloudSmith.Identity.Users.PostgresUserService>();
builder.Services.AddScoped<IGroupService, PostgresGroupService>();  // AB#1469

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

    // Setup policy (C2 security fix): max 5 attempts per 15 min per IP — prevents
    // brute-force guessing of the initial admin token before first-run completes.
    opts.AddPolicy(CloudSmith.Api.Endpoints.SetupEndpoints.SetupRateLimitPolicy, ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit          = 5,
                Window               = TimeSpan.FromMinutes(15),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit           = 0,
            }));
});

// Relay WebSocket hub — in-memory registry of connected relay sockets (AB#1679)
builder.Services.AddSingleton<IConnectedRelayRegistry, ConnectedRelayRegistry>();

// AB#1931 — In-process job batch processor (Phase IV; replaced by durable worker in Phase V).
builder.Services.AddSingleton<CloudSmith.Api.Services.IJobBatchProcessor, CloudSmith.Api.Services.InProcessJobBatchProcessor>();

// AB#1932 — Notification service for job completion/failure events.
builder.Services.AddScoped<CloudSmith.Api.Services.INotificationService, CloudSmith.Api.Services.PostgresNotificationService>();

// AB#1933 — HttpClient for Microsoft Graph calls (Entra auto-create flow).
builder.Services.AddHttpClient("graph");

// AB#1925 — Published module catalog: proxies GHCR registry + merges local install state.
// Anonymous access is sufficient for catalog browsing; HttpClient configured with GitHub API headers.
builder.Services.AddHttpClient<IModuleCatalogService, GhcrModuleCatalogService>(client =>
{
    client.BaseAddress = new Uri("https://api.github.com");
    client.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
    client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
    client.DefaultRequestHeaders.Add("User-Agent", "cloudsmith-api/catalog");
});

// AB#1952 — Platform update check: anonymous HttpClient for GHCR manifest queries.
builder.Services.AddHttpClient("ghcr-update", client =>
{
    client.DefaultRequestHeaders.Add("User-Agent", "cloudsmith-api/update-check");
});

// AB#1952 — IMemoryCache for caching GHCR digest lookups (15-minute TTL).
builder.Services.AddMemoryCache();

// AB#1591 — First-startup bootstrap: generate master secrets key + write initial admin token.
// Registered as a singleton so SetupEndpoints can inject it for token validation (C2 security fix).
// AddHostedService with a factory resolves the same singleton instance for IHostedService.
builder.Services.AddSingleton<MasterSecretsKeyBootstrap>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<MasterSecretsKeyBootstrap>());

var app = builder.Build();

// Run all module migrations on startup using isolated scopes to avoid FM runner conflicts.
// CLOUDSMITH_SKIP_MIGRATIONS skips this in environments without a live DB (e.g. OpenAPI spec gen in CI).
if (!string.Equals(Environment.GetEnvironmentVariable("CLOUDSMITH_SKIP_MIGRATIONS"), "true", StringComparison.OrdinalIgnoreCase))
{
    app.Services.MigrateCloudSmithDatabase();
    MigrateAllDatabases(connectionString);
}

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
// User CRUD endpoints from identity module — GET/POST/PATCH/DELETE /api/v1/users (AB#1468)
app.MapUserEndpoints();

// ADR-047 first-run setup + local login endpoints (anonymous)
app.MapSetupEndpoints();

// API endpoints
app.MapConfigEndpoints();
app.MapClusterEndpoints();
app.MapJobEndpoints();             // AB#1429 async job status + log
app.MapInventoryEndpoints();
app.MapPlatformEndpoints();   // AB#1640-1642 Modules (Platform Management group)
app.MapIdentityProviderEndpoints();   // AB#1643-1647 Identity Providers CRUD
app.MapGroupEndpoints();              // AB#1469 Group CRUD + membership + role mapping
app.MapUsersEndpoints();              // AB#1648-1649 Users + invite
app.MapAuditEndpoints();              // AB#1651 Audit log query
app.MapSitesEndpoints();              // AB#1652 Sites CRUD
app.MapSecretsEndpoints();            // AB#1653 Secrets refs CRUD
app.MapRelayEndpoints();              // AB#1670 Relay bridge — enrollment, clusters POST, inventory ingest, health probe
app.MapHardwareCatalogEndpoints();    // AB#1496 hardware catalog profiles + drift reports
app.MapPermissionsEndpoints();        // AB#1422 /auth/v1/me/permissions — caller's effective permission set
app.MapPlatformAuditEndpoints();      // AB#1929 POST /api/v1/platform/audit — portal-originated audit event ingest
app.MapDashboardLayoutEndpoints();    // AB#1930 GET/PATCH /api/v1/users/me/dashboard-layout
app.MapJobBatchEndpoints();           // AB#1931 POST /api/v1/jobs/batch — bulk job batching
app.MapNotificationsEndpoints();      // AB#1932 GET/PATCH /api/v1/notifications
app.MapPlatformIdentityProviderEndpoints(); // AB#1933 POST/GET /api/v1/platform/identity/providers — AB#1934 consent-callback
app.MapModuleCatalogEndpoints();            // AB#1925 GET /api/v1/modules/catalog, POST/DELETE /api/v1/modules/{id} — AB#1959 updateAvailable
app.MapPlatformUpdateEndpoints();           // AB#1952 GET /api/v1/platform/updates/check — AB#1953 PUT /api/v1/platform/updates/apply

// SignalR PlatformHub — real-time events for portal and runners (AB#1436).
// Requires JWT Bearer or cookie auth (handled by ASP.NET Core middleware).
// Browser WebSocket auth: pass access_token query param (SignalR convention).
app.MapHub<PlatformHub>("/hubs/platform");

// OpenAPI / Scalar docs
// Primary endpoint: /openapi/v1.json (ASP.NET Core 9 default)
app.MapOpenApi();
// Swagger-compat alias: /swagger/v1/swagger.json — AB#1440
// Allows tooling that expects the Swashbuckle path to resolve the spec.
app.MapOpenApi("/swagger/v1/swagger.json");
app.MapScalarApiReference();

app.Run();

// Runs FluentMigrator for the API project, cluster-mgmt, and inventory in separate
// isolated scopes. Each module's AddXxx() registers its own FM runner; calling them
// all on the main service collection would cause the last registration to overwrite
// the first. Isolated scopes ensure each assembly's migrations run correctly.
static void MigrateAllDatabases(string connectionString)
{
    // AB#1591 — API-project migrations (bootstrap_config, etc.)
    RunMigrations(connectionString, typeof(Program).Assembly);
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
