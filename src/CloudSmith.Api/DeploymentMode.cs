// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

namespace CloudSmith.Api;

/// <summary>
/// AB#1601 — Deployment topology the API is running in.
/// Parsed from the <c>CLOUDSMITH_DEPLOYMENT_MODE</c> environment variable at startup.
/// Controls which OpenTelemetry exporter is wired (OTLP vs Azure Monitor).
/// </summary>
public enum DeploymentMode
{
    /// <summary>
    /// Standalone on-premises deployment. OTel traces are exported via OTLP to
    /// a local otel-collector sidecar.
    /// </summary>
    Standalone,

    /// <summary>
    /// Azure PaaS deployment (Azure Container Apps). OTel traces are exported via
    /// Azure Monitor / Application Insights using the
    /// <c>appinsights_connection_string</c> configuration value.
    /// </summary>
    PaaS,
}
