// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using CloudSmith.Api.Services;
using CloudSmith.Core.Setup;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// ADR-047 — first-run setup + local (break-glass) login endpoints. All anonymous:
/// they are reachable before any IdP or admin exists. Once setup is complete,
/// <c>POST /api/v1/setup</c> is permanently locked (409).
/// C2 security fix: token TTL enforced (410 Gone on expired token) and setup endpoint
/// is rate-limited at 5 attempts per 15 minutes per IP.
/// </summary>
public static class SetupEndpoints
{
    /// <summary>Rate limiter policy name for <c>POST /api/v1/setup</c> (C2 security fix).</summary>
    public const string SetupRateLimitPolicy = "setup-limit";

    public sealed record CompleteSetupRequest(
        string PlatformName, string PublicUrl, string AdminUsername,
        string? AdminEmail, string AdminPassword, string? Timezone,
        /// <summary>
        /// One-time initial admin token written to the secrets file on first boot.
        /// Required — rejected with 401 if absent, 410 if expired, 401 if invalid.
        /// </summary>
        string? InitialAdminToken);

    public sealed record LocalLoginRequest(string Username, string Password);

    public static IEndpointRouteBuilder MapSetupEndpoints(this IEndpointRouteBuilder app)
    {
        // Anonymous — the portal calls this on load to decide wizard vs. login.
        app.MapGet("/api/v1/setup/status", async (SetupService setup, CancellationToken ct) =>
        {
            var status = await setup.GetStatusAsync(ct);
            return Results.Ok(new { setupComplete = status.SetupComplete, platformName = status.PlatformName, publicUrl = status.PublicUrl });
        });

        // Anonymous — performs first-run setup once; 409 if already complete.
        // C2: rate-limited (5 attempts per 15 min per IP) and validates the initial admin token.
        app.MapPost("/api/v1/setup", async (
            CompleteSetupRequest req,
            SetupService setup,
            MasterSecretsKeyBootstrap bootstrap,
            CancellationToken ct) =>
        {
            // Validate the one-time initial admin token (C2 — enforces TTL).
            if (string.IsNullOrWhiteSpace(req.InitialAdminToken))
            {
                return Results.Json(
                    new { error = "token-required", message = "A valid initial admin token is required to complete setup." },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            var tokenResult = await bootstrap.ValidateInitialAdminTokenAsync(req.InitialAdminToken, ct);
            switch (tokenResult)
            {
                case TokenValidationResult.Expired:
                    return Results.Json(
                        new { error = "token-expired", message = "The initial admin token has expired (30-minute TTL). Restart the CloudSmith service to generate a new token." },
                        statusCode: StatusCodes.Status410Gone);

                case TokenValidationResult.NotFound:
                case TokenValidationResult.Invalid:
                    return Results.Json(
                        new { error = "token-invalid", message = "The initial admin token is invalid." },
                        statusCode: StatusCodes.Status401Unauthorized);
            }

            try
            {
                await setup.CompleteSetupAsync(
                    req.PlatformName, req.PublicUrl, req.AdminUsername,
                    req.AdminEmail ?? string.Empty, req.AdminPassword, req.Timezone, ct);

                // Revoke the one-time token now that setup is complete.
                await bootstrap.RevokeInitialAdminTokenAsync(ct);

                return Results.Ok(new { setupComplete = true });
            }
            catch (InvalidOperationException ex)
            {
                return Results.Conflict(new { error = "setup-already-complete", message = ex.Message });
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(new { error = "invalid-setup-request", message = ex.Message });
            }
        })
        .RequireRateLimiting(SetupRateLimitPolicy);

        // Anonymous — local (break-glass) login. Verifies the credential and issues the
        // same cookie session the OIDC path uses, so /api/v1/auth/me works identically.
        app.MapPost("/api/v1/auth/local-login", async (LocalLoginRequest req, SetupService setup, HttpContext ctx, CancellationToken ct) =>
        {
            var principal = await setup.VerifyCredentialsAsync(req.Username, req.Password, ct);
            if (principal is null)
                return Results.Json(new { error = "invalid-credentials" }, statusCode: StatusCodes.Status401Unauthorized);

            var claims = new List<Claim>
            {
                new("sub", principal.UserId.ToString()),
                new("email", principal.Email),
                new("preferred_username", principal.Username),
                new("org_id", principal.OrgId.ToString()),
            };
            claims.AddRange(principal.Roles.Select(r => new Claim("realm_roles", r)));

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            return Results.Ok(new
            {
                sub = principal.UserId.ToString(),
                email = principal.Email,
                username = principal.Username,
                orgId = principal.OrgId.ToString(),
                roles = principal.Roles,
            });
        });

        return app;
    }
}

/// <summary>
/// Blocks all non-allowlisted API traffic until first-run setup is complete (ADR-047).
/// Runs before authentication so the setup wizard and local login work with no IdP.
/// </summary>
public sealed class SetupGateMiddleware
{
    private readonly RequestDelegate _next;

    public SetupGateMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx, SetupService setup)
    {
        var path = ctx.Request.Path.Value ?? string.Empty;

        if (IsAllowlisted(path))
        {
            await _next(ctx);
            return;
        }

        var status = await setup.GetStatusAsync(ctx.RequestAborted);
        if (!status.SetupComplete)
        {
            ctx.Response.StatusCode = StatusCodes.Status409Conflict;
            await ctx.Response.WriteAsJsonAsync(new
            {
                error = "setup-required",
                message = "Platform setup is not complete. Complete first-run setup at /setup.",
            });
            return;
        }

        await _next(ctx);
    }

    private static bool IsAllowlisted(string path) =>
        path.StartsWith("/api/v1/setup", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/v1/auth/local-login", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/v1/auth/login", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/v1/auth/callback", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/signin-oidc", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/health", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/openapi", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/scalar", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/", StringComparison.Ordinal);
}
