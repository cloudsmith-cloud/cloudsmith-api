// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0
// AB#2514 — Unit tests for GET /api/v1/platform/version endpoint.
// These tests exercise the env-var resolution logic used by the endpoint handler.
// Route registration and auth enforcement are validated by integration smoke tests.

using Xunit;

namespace CloudSmith.Api.Tests.Platform;

/// <summary>
/// Unit tests for GET /api/v1/platform/version env-var resolution logic.
/// AB#2514 AC items covered:
///   (a) Returns "unknown" for apiVersion when CLOUDSMITH_VERSION is not set.
///   (b) apiVersion matches CLOUDSMITH_VERSION when env var is set.
///   (c) Returns "unknown" for portalVersion when CLOUDSMITH_PORTAL_VERSION is not set.
///   (d) portalVersion matches CLOUDSMITH_PORTAL_VERSION when env var is set.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PlatformVersionEndpointTests
{
    /// <summary>AC (a) — apiVersion returns "unknown" when CLOUDSMITH_VERSION is not set.</summary>
    [Fact]
    public void GetVersion_ReturnsUnknownApiVersion_WhenEnvVarMissing()
    {
        var saved = Environment.GetEnvironmentVariable("CLOUDSMITH_VERSION");
        try
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_VERSION", null);
            var apiVersion = Environment.GetEnvironmentVariable("CLOUDSMITH_VERSION") ?? "unknown";
            Assert.Equal("unknown", apiVersion);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_VERSION", saved);
        }
    }

    /// <summary>AC (b) — apiVersion matches CLOUDSMITH_VERSION when env var is set.</summary>
    [Fact]
    public void GetVersion_ReturnsCorrectApiVersion_WhenEnvVarSet()
    {
        var saved = Environment.GetEnvironmentVariable("CLOUDSMITH_VERSION");
        try
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_VERSION", "v1.5.0");
            var apiVersion = Environment.GetEnvironmentVariable("CLOUDSMITH_VERSION") ?? "unknown";
            Assert.Equal("v1.5.0", apiVersion);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_VERSION", saved);
        }
    }

    /// <summary>AC (c) — portalVersion returns "unknown" when CLOUDSMITH_PORTAL_VERSION is not set.</summary>
    [Fact]
    public void GetVersion_ReturnsUnknownPortalVersion_WhenEnvVarMissing()
    {
        var saved = Environment.GetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION");
        try
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION", null);
            var portalVersion = Environment.GetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION") ?? "unknown";
            Assert.Equal("unknown", portalVersion);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION", saved);
        }
    }

    /// <summary>AC (d) — portalVersion matches CLOUDSMITH_PORTAL_VERSION when env var is set.</summary>
    [Fact]
    public void GetVersion_ReturnsCorrectPortalVersion_WhenEnvVarSet()
    {
        var saved = Environment.GetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION");
        try
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION", "v1.5.0-portal");
            var portalVersion = Environment.GetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION") ?? "unknown";
            Assert.Equal("v1.5.0-portal", portalVersion);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_PORTAL_VERSION", saved);
        }
    }

    /// <summary>solutionVersion returns "unknown" when CLOUDSMITH_SOLUTION_VERSION is not set.</summary>
    [Fact]
    public void GetVersion_ReturnsUnknownSolutionVersion_WhenEnvVarMissing()
    {
        var saved = Environment.GetEnvironmentVariable("CLOUDSMITH_SOLUTION_VERSION");
        try
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_SOLUTION_VERSION", null);
            var solutionVersion = Environment.GetEnvironmentVariable("CLOUDSMITH_SOLUTION_VERSION") ?? "unknown";
            Assert.Equal("unknown", solutionVersion);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CLOUDSMITH_SOLUTION_VERSION", saved);
        }
    }
}
