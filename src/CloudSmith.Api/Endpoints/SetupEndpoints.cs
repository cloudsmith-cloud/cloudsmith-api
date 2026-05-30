// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using CloudSmith.Api.Services;
using CloudSmith.Api.Substrate;
using CloudSmith.Core.Setup;
using CloudSmith.Core.Substrate;
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
        /// AB#2412 — When true and running on PaaS, the API will attempt to create an
        /// Entra app registration automatically via Microsoft Graph using the ACA Managed
        /// Identity. Requires the MI to hold the Entra Application Administrator role.
        /// If auto-create is not possible (missing permissions or non-PaaS substrate),
        /// setup still completes and the response includes <c>entraAutoCreateError</c>
        /// and <c>entraManualInstructions</c> so the operator can create the app manually.
        /// </summary>
        bool? AutoCreateAppRegistration,
        /// <summary>
        /// Public FQDN of the portal (e.g. "myplatform.azurecontainerapps.io").
        /// Required when <see cref="AutoCreateAppRegistration"/> is true.
        /// Used to set the Entra redirect URI to "https://{PortalFqdn}/signin-oidc".
        /// </summary>
        string? PortalFqdn);

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
        // Rate-limited (5 attempts per 15 min per IP).
        // AB#2412: optional autoCreateAppRegistration flag — provisions Entra app via Graph MI.
        app.MapPost("/api/v1/setup", async (
            CompleteSetupRequest req,
            SetupService setup,
            ISubstrateAdapter substrate,
            IHttpClientFactory httpClientFactory,
            CancellationToken ct) =>
        {

            // AB#2412 — Entra auto-create via Managed Identity Graph call.
            // Attempted before completing setup so a Graph error still returns before setup is
            // marked complete — the operator can then fix permissions and retry.
            // Non-fatal: if auto-create fails we include the error in the response but still
            // complete setup so the operator can configure Entra manually afterward.
            string? entraClientId      = null;
            string? entraTenantId      = null;
            string? entraClientSecret  = null;
            string? entraAutoCreateError       = null;
            string? entraManualInstructions    = null;

            var wantAutoCreate = req.AutoCreateAppRegistration ?? false;
            var doAutoCreate   = wantAutoCreate
                                 && substrate is PaaSAdapter
                                 && !string.IsNullOrWhiteSpace(req.PortalFqdn);

            if (doAutoCreate)
            {
                var paasAdapter = (PaaSAdapter)substrate;
                var entraResult = await paasAdapter.TryCreateEntraAppRegistrationAsync(
                    req.PortalFqdn!, httpClientFactory, ct);

                if (entraResult.Success)
                {
                    entraClientId     = entraResult.ClientId;
                    entraTenantId     = entraResult.TenantId;
                    entraClientSecret = entraResult.ClientSecret;

                    // Persist the credentials into Key Vault so the platform can use them after setup.
                    await substrate.SetSecretAsync("cloudsmith-entra-client-id",     entraClientId!,     ct: ct);
                    await substrate.SetSecretAsync("cloudsmith-entra-tenant-id",     entraTenantId!,     ct: ct);
                    await substrate.SetSecretAsync("cloudsmith-entra-client-secret", entraClientSecret!, ct: ct);
                }
                else
                {
                    entraAutoCreateError    = entraResult.Error;
                    entraManualInstructions = entraResult.ManualInstructions;
                }
            }
            else if (wantAutoCreate && substrate is not PaaSAdapter)
            {
                entraAutoCreateError = "autoCreateAppRegistration is only supported on PaaS deployments. " +
                                       "Configure Entra manually using the platform identity provider settings.";
            }
            else if (wantAutoCreate && string.IsNullOrWhiteSpace(req.PortalFqdn))
            {
                entraAutoCreateError = "portalFqdn is required when autoCreateAppRegistration=true.";
            }

            try
            {
                await setup.CompleteSetupAsync(
                    req.PlatformName, req.PublicUrl, req.AdminUsername,
                    req.AdminEmail ?? string.Empty, req.AdminPassword, req.Timezone, ct);

                return Results.Ok(new
                {
                    setupComplete          = true,
                    entraClientId,
                    entraTenantId,
                    // clientSecret is returned once here — not stored in the response body after this call.
                    entraClientSecret,
                    entraAutoCreateError,
                    entraManualInstructions,
                });
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
        || path.StartsWith("/api/v1/platform/identity/consent-callback", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/signin-oidc", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/health", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/openapi", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/scalar", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/", StringComparison.Ordinal);
}
