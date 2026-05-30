// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CloudSmith.Api.Authorization;
using CloudSmith.Api.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Platform-level identity provider registration — AB#1933.
///
/// POST /api/v1/platform/identity/providers
///   type=entra + autoCreate=true  → calls Microsoft Graph to provision an app registration,
///                                    creates a client secret, stores tenantId/clientId/encryptedSecret.
///   type=entra + autoCreate=false → stores the provided tenantId/clientId/clientSecret (encrypted).
///   type=oidc                     → stores the provided configuration (secret encrypted).
///
/// GET /api/v1/platform/identity/providers
///   Returns configured providers (never returns secret values).
///
/// Secret encryption: AES-256-GCM with the master key loaded from the file / env var that
/// MasterSecretsKeyBootstrap writes at startup. Format: base64(nonce || ciphertext || tag).
/// Requires platform:write (POST) / platform:read (GET).
/// </summary>
public static class PlatformIdentityProviderEndpoints
{
    // Microsoft Graph endpoint for app registration.
    private const string GraphApplicationsUrl = "https://graph.microsoft.com/v1.0/applications";

    private static readonly HashSet<string> AllowedTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "entra", "oidc",
    };

    public sealed record RegisterProviderRequest(
        string Type,
        bool? AutoCreate,
        string? TenantId,
        string? AdminConsent,
        string? ClientId,
        string? ClientSecret);

    public sealed record RegisterProviderResponse(
        string ProviderId,
        string Type,
        string? TenantId,
        string? ClientId,
        string? ClientSecret);

    public sealed record ProviderSummaryResponse(
        string ProviderId,
        string Type,
        string? TenantId,
        string? ClientId,
        string Status,
        string CreatedAt);

    public static IEndpointRouteBuilder MapPlatformIdentityProviderEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/platform/identity").WithTags("Platform");

        // GET /api/v1/platform/identity — returns platform name, public URL, and setup state.
        // Used by the portal top bar to display the operator-configured platform name.
        group.MapGet("", async (SetupService setup, CancellationToken ct) =>
        {
            var status = await setup.GetStatusAsync(ct);
            return Results.Ok(new
            {
                platformName = status.PlatformName,
                publicUrl    = status.PublicUrl,
                setupState   = status.SetupComplete ? "Completed" : "Pending",
                timezone     = (string?)null,
            });
        });

        // POST /api/v1/platform/identity/consent-callback — AB#1934.
        // Anonymous redirect target after Entra OAuth admin-consent popup.
        // Broadcasts the authorization code to the portal via BroadcastChannel, then closes the popup.
        group.MapPost("/consent-callback", (HttpContext ctx) =>
        {
            var code = ctx.Request.Query["code"].FirstOrDefault() ?? string.Empty;

            // HTML-encode the code to prevent XSS before injecting into the script tag.
            var safeCode = System.Net.WebUtility.HtmlEncode(code);

            var html = $$"""
                <!DOCTYPE html><html><body><script>
                new BroadcastChannel('cloudsmith-oauth-callback').postMessage({type:'consent-code',code:'{{safeCode}}'});
                window.close();
                </script></body></html>
                """;

            return Results.Content(html, "text/html");
        })
        .AllowAnonymous()
        .WithSummary("Entra OAuth consent redirect target — posts auth code to BroadcastChannel and closes the popup. AB#1934.");

        // GET /api/v1/platform/identity/providers — list configured providers, no secret values.
        group.MapGet("/providers", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            const string sql = """
                SELECT provider_id, provider_type, tenant_id, client_id, status, created_at
                FROM core.platform_identity_providers
                ORDER BY created_at DESC
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);

            var results = new List<ProviderSummaryResponse>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                results.Add(new ProviderSummaryResponse(
                    ProviderId: reader.GetGuid(0).ToString(),
                    Type: reader.GetString(1),
                    TenantId: reader.IsDBNull(2) ? null : reader.GetString(2),
                    ClientId: reader.IsDBNull(3) ? null : reader.GetString(3),
                    Status: reader.GetString(4),
                    CreatedAt: reader.GetDateTime(5).ToUniversalTime().ToString("o")));
            }

            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("List configured platform identity providers (secret values never returned). AB#1933.");

        // POST /api/v1/platform/identity/providers — register a new provider.
        group.MapPost("/providers", async (
            RegisterProviderRequest req,
            NpgsqlDataSource db,
            IHttpClientFactory httpClientFactory,
            MasterSecretsKeyBootstrap masterKeyBootstrap,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(req.Type) || !AllowedTypes.Contains(req.Type))
            {
                return Results.Json(
                    new { error = "invalid-type", message = $"type must be one of: {string.Join(", ", AllowedTypes)}." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            string? tenantId = req.TenantId;
            string? clientId = req.ClientId;
            string? plaintextSecret = req.ClientSecret;
            bool autoCreated = false;

            var providerType = req.Type.ToLowerInvariant();
            var autoCreate = req.AutoCreate ?? false;

            if (providerType == "entra" && autoCreate)
            {
                // Entra Graph auto-create flow.
                if (string.IsNullOrWhiteSpace(req.AdminConsent))
                {
                    return Results.Json(
                        new { error = "missing-admin-consent", message = "adminConsent token is required when autoCreate=true." },
                        statusCode: StatusCodes.Status400BadRequest);
                }
                if (string.IsNullOrWhiteSpace(req.TenantId))
                {
                    return Results.Json(
                        new { error = "missing-tenant-id", message = "tenantId is required when autoCreate=true." },
                        statusCode: StatusCodes.Status400BadRequest);
                }

                // Use the admin consent token (from portal OAuth popup) to call Graph.
                var (graphClientId, graphSecret, graphError) =
                    await ProvisionEntraAppAsync(httpClientFactory, req.AdminConsent, req.TenantId, ct);

                if (graphError is not null)
                    return Results.Json(new { error = "graph-provisioning-failed", message = graphError }, statusCode: StatusCodes.Status502BadGateway);

                clientId = graphClientId;
                plaintextSecret = graphSecret;
                autoCreated = true;
            }
            else if (providerType == "entra" && !autoCreate)
            {
                // Manual Entra config — all fields must be supplied.
                if (string.IsNullOrWhiteSpace(req.TenantId))
                    return Results.Json(new { error = "missing-tenant-id" }, statusCode: StatusCodes.Status400BadRequest);
                if (string.IsNullOrWhiteSpace(req.ClientId))
                    return Results.Json(new { error = "missing-client-id" }, statusCode: StatusCodes.Status400BadRequest);
                if (string.IsNullOrWhiteSpace(req.ClientSecret))
                    return Results.Json(new { error = "missing-client-secret" }, statusCode: StatusCodes.Status400BadRequest);
            }
            else if (providerType == "oidc")
            {
                if (string.IsNullOrWhiteSpace(req.ClientId))
                    return Results.Json(new { error = "missing-client-id" }, statusCode: StatusCodes.Status400BadRequest);
                // clientSecret may be null for OIDC public clients.
            }

            // Encrypt the client secret with the master key before persisting.
            string? encryptedSecret = null;
            if (!string.IsNullOrWhiteSpace(plaintextSecret))
            {
                var masterKey = masterKeyBootstrap.LoadMasterKey();
                if (masterKey is null)
                {
                    return Results.Json(
                        new { error = "master-key-unavailable", message = "The platform master key could not be loaded. Ensure the API has started correctly." },
                        statusCode: StatusCodes.Status500InternalServerError);
                }
                encryptedSecret = EncryptSecret(plaintextSecret, masterKey);
            }

            // Persist.
            Guid providerId;
            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO core.platform_identity_providers
                    (provider_type, tenant_id, client_id, client_secret_enc, auto_created)
                VALUES
                    (@provider_type, @tenant_id, @client_id, @client_secret_enc, @auto_created)
                RETURNING provider_id
                """, conn);
            cmd.Parameters.Add(new NpgsqlParameter("@provider_type", NpgsqlDbType.Text) { Value = providerType });
            cmd.Parameters.Add(new NpgsqlParameter("@tenant_id", NpgsqlDbType.Text)
                { Value = tenantId is null ? DBNull.Value : (object)tenantId });
            cmd.Parameters.Add(new NpgsqlParameter("@client_id", NpgsqlDbType.Text)
                { Value = clientId is null ? DBNull.Value : (object)clientId });
            cmd.Parameters.Add(new NpgsqlParameter("@client_secret_enc", NpgsqlDbType.Text)
                { Value = encryptedSecret is null ? DBNull.Value : (object)encryptedSecret });
            cmd.Parameters.Add(new NpgsqlParameter("@auto_created", NpgsqlDbType.Boolean)
                { Value = autoCreated });

            var scalar = await cmd.ExecuteScalarAsync(ct);
            providerId = (Guid)scalar!;

            // Return the plaintext secret one-time only.
            // Portal shows a SecretReveal component; after this response it is not accessible.
            var response = new RegisterProviderResponse(
                ProviderId: providerId.ToString(),
                Type: providerType,
                TenantId: tenantId,
                ClientId: clientId,
                ClientSecret: plaintextSecret);

            return Results.Created($"/api/v1/platform/identity/providers/{providerId}", response);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Register a platform identity provider. Entra autoCreate=true provisions via Graph. Returns clientSecret once (one-time reveal). AB#1933.");

        return app;
    }

    // -------------------------------------------------------------------------
    // Microsoft Graph provisioning — Entra app registration
    // -------------------------------------------------------------------------

    /// <summary>
    /// Provisions an Entra app registration via Microsoft Graph using the admin consent
    /// token obtained from the portal's OAuth popup. Creates a client secret and returns
    /// (clientId, clientSecret, null) on success or (null, null, errorMessage) on failure.
    /// </summary>
    private static async Task<(string? ClientId, string? ClientSecret, string? Error)>
        ProvisionEntraAppAsync(
            IHttpClientFactory httpClientFactory,
            string adminConsentToken,
            string tenantId,
            CancellationToken ct)
    {
        using var http = httpClientFactory.CreateClient("graph");
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", adminConsentToken);

        // Create the application registration.
        var appBody = new
        {
            displayName = "CloudSmith Platform",
            signInAudience = "AzureADMyOrg",
            web = new
            {
                redirectUris = new[]
                {
                    "https://cloudsmith.local/auth/v1/callback",
                    "https://cloudsmith.local/signin-oidc",
                },
            },
            requiredResourceAccess = new[]
            {
                new
                {
                    resourceAppId = "00000003-0000-0000-c000-000000000000", // Microsoft Graph
                    resourceAccess = new[]
                    {
                        new { id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d", type = "Scope" }, // User.Read
                        new { id = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182", type = "Scope" }, // offline_access
                        new { id = "37f7f235-527c-4136-accd-4a02d197296e", type = "Scope" }, // openid
                        new { id = "14dad69e-099b-42c9-810b-d002981feec1", type = "Scope" }, // profile
                    },
                },
            },
        };

        string? appId;
        string? objectId;
        try
        {
            var createResp = await http.PostAsync(
                GraphApplicationsUrl,
                new StringContent(JsonSerializer.Serialize(appBody), Encoding.UTF8, "application/json"),
                ct);

            if (!createResp.IsSuccessStatusCode)
            {
                var body = await createResp.Content.ReadAsStringAsync(ct);
                return (null, null, $"Graph POST /applications returned {(int)createResp.StatusCode}: {Truncate(body, 200)}");
            }

            using var appDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync(ct));
            appId = appDoc.RootElement.TryGetProperty("appId", out var appIdEl) ? appIdEl.GetString() : null;
            objectId = appDoc.RootElement.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;

            if (string.IsNullOrEmpty(appId) || string.IsNullOrEmpty(objectId))
                return (null, null, "Graph returned an application without an appId or object id.");
        }
        catch (Exception ex)
        {
            return (null, null, $"Graph application creation failed: {ex.Message}");
        }

        // Create a client secret for the new application.
        string? secretValue;
        try
        {
            var addPasswordBody = new
            {
                passwordCredential = new
                {
                    displayName = "CloudSmith Platform Secret",
                    endDateTime = DateTime.UtcNow.AddYears(2).ToString("o"),
                },
            };

            var secretResp = await http.PostAsync(
                $"{GraphApplicationsUrl}/{objectId}/addPassword",
                new StringContent(JsonSerializer.Serialize(addPasswordBody), Encoding.UTF8, "application/json"),
                ct);

            if (!secretResp.IsSuccessStatusCode)
            {
                var body = await secretResp.Content.ReadAsStringAsync(ct);
                return (null, null, $"Graph POST /addPassword returned {(int)secretResp.StatusCode}: {Truncate(body, 200)}");
            }

            using var secretDoc = JsonDocument.Parse(await secretResp.Content.ReadAsStringAsync(ct));
            secretValue = secretDoc.RootElement.TryGetProperty("secretText", out var stEl) ? stEl.GetString() : null;

            if (string.IsNullOrEmpty(secretValue))
                return (null, null, "Graph addPassword response did not include secretText.");
        }
        catch (Exception ex)
        {
            return (null, null, $"Graph addPassword failed: {ex.Message}");
        }

        return (appId, secretValue, null);
    }

    // -------------------------------------------------------------------------
    // AES-256-GCM encryption
    // -------------------------------------------------------------------------

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with AES-256-GCM using <paramref name="keyBytes"/>.
    /// Returns a base64-encoded envelope: nonce(12) || ciphertext(n) || tag(16).
    /// </summary>
    private static string EncryptSecret(string plaintext, byte[] keyBytes)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using var aes = new AesGcm(keyBytes, AesGcm.TagByteSizes.MaxSize);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // Envelope: nonce || ciphertext || tag
        var envelope = new byte[nonce.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, envelope, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, envelope, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, envelope, nonce.Length + ciphertext.Length, tag.Length);

        return Convert.ToBase64String(envelope);
    }

    private static string Truncate(string s, int max) =>
        s.Length > max ? s[..max] + "…" : s;
}
