// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Authorization;
using CloudSmith.Api.Endpoints;
using CloudSmith.Core.Hosting;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
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
            builder.Configuration["Otel:Endpoint"] ?? "http://localhost:4317")));

// Platform kernel (migrations + RBAC + Config + health)
var connectionString = builder.Configuration.GetConnectionString("CloudSmith")
    ?? throw new InvalidOperationException("CS-CORE-ERR-001: Required configuration 'ConnectionStrings:CloudSmith' is missing");
builder.Services.AddCloudSmithCore(connectionString);

// API-layer services
builder.Services.AddCloudSmithAuthorization();
builder.Services.AddOpenApi();

var app = builder.Build();

// Run pending migrations on startup
app.Services.MigrateCloudSmithDatabase();

// Middleware
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<TenantContextMiddleware>();

// Health endpoints per health-check-contract.md
app.MapHealthEndpoints();

// API endpoints
app.MapConfigEndpoints();

// OpenAPI / Scalar docs
app.MapOpenApi();
app.MapScalarApiReference();

app.Run();

// Expose for integration testing
public partial class Program { }
