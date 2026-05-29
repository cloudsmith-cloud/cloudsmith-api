// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.AppContainers;
using Azure.Security.KeyVault.Secrets;
using CloudSmith.Core.Substrate;
using Microsoft.Extensions.Logging;

namespace CloudSmith.Api.Substrate;

/// <summary>
/// AB#2354 — PaaS (Azure Container Apps) substrate adapter.
/// Secrets → Azure Key Vault via DefaultAzureCredential + Managed Identity.
/// Image update → ACA revision swap via ARM SDK.
/// AB#2412 — TryCreateEntraAppRegistrationAsync: creates an Entra app registration via
/// Microsoft Graph using the ACA managed identity when it holds the
/// Entra Application Administrator role.
/// </summary>
internal sealed class PaaSAdapter : ISubstrateAdapter
{
    private readonly SecretClient _kv;
    private readonly string _kvName;
    private readonly ILogger<PaaSAdapter> _logger;

    public SubstrateMode Mode => SubstrateMode.PaaS;

    public PaaSAdapter(string kvName, ILogger<PaaSAdapter> logger)
    {
        _kvName = kvName;
        _kv     = new SecretClient(new Uri($"https://{kvName}.vault.azure.net/"), new DefaultAzureCredential());
        _logger = logger;
    }

    // ---- Secrets ------------------------------------------------------------

    public async Task<string?> GetSecretAsync(string name, CancellationToken ct = default)
    {
        try
        {
            var response = await _kv.GetSecretAsync(name, cancellationToken: ct).ConfigureAwait(false);
            return response.Value.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async Task SetSecretAsync(string name, string value, DateTimeOffset? expiresOn = null, CancellationToken ct = default)
    {
        var secret = new KeyVaultSecret(name, value)
        {
            Properties =
            {
                ExpiresOn   = expiresOn,
                ContentType = "text/plain",
            }
        };
        secret.Properties.Tags["managed-by"] = "cloudsmith-api";
        await _kv.SetSecretAsync(secret, ct).ConfigureAwait(false);
    }

    public async Task DeleteSecretAsync(string name, CancellationToken ct = default)
    {
        try
        {
            await _kv.StartDeleteSecretAsync(name, ct).ConfigureAwait(false);
        }
        catch (RequestFailedException ex) when (ex.Status == 404) { /* already gone */ }
    }

    // ---- Operator artifacts -------------------------------------------------

    public async Task WriteOperatorArtifactAsync(string logicalName, string content, ArtifactKind kind, DateTimeOffset? expiresOn = null, CancellationToken ct = default)
    {
        // All artifact kinds on PaaS go to KV with a kind tag.
        var secret = new KeyVaultSecret(logicalName, content)
        {
            Properties =
            {
                ContentType = "text/plain",
                ExpiresOn   = expiresOn,
            }
        };
        secret.Properties.Tags["managed-by"] = "cloudsmith-api";
        secret.Properties.Tags["kind"]       = kind.ToString().ToLowerInvariant();
        await _kv.SetSecretAsync(secret, ct).ConfigureAwait(false);

        _logger.LogInformation(
            "Operator artifact '{LogicalName}' (kind={Kind}) written to Key Vault '{Vault}'.",
            logicalName, kind, _kvName);
    }

    public string GetOperatorRetrievalHint(string logicalName) =>
        $"az keyvault secret show --vault-name {_kvName} --name {logicalName} --query value -o tsv";

    // ---- Platform lifecycle -------------------------------------------------

    public async Task TriggerImageUpdateAsync(string imageRef, CancellationToken ct = default)
    {
        var subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID");
        var resourceGroup  = Environment.GetEnvironmentVariable("CLOUDSMITH_ACA_RESOURCE_GROUP");

        if (string.IsNullOrWhiteSpace(subscriptionId) || string.IsNullOrWhiteSpace(resourceGroup))
            throw new InvalidOperationException(
                "AZURE_SUBSCRIPTION_ID and CLOUDSMITH_ACA_RESOURCE_GROUP must be set for PaaS image update.");

        var acaAppName = Environment.GetEnvironmentVariable("CLOUDSMITH_ACA_APP_NAME") ?? "ca-cloudsmith-api";

        var armClient = new ArmClient(new DefaultAzureCredential());
        var appId     = ContainerAppResource.CreateResourceIdentifier(subscriptionId, resourceGroup, acaAppName);
        var apiApp    = armClient.GetContainerAppResource(appId);
        var current   = await apiApp.GetAsync(ct).ConfigureAwait(false);

        await apiApp.UpdateAsync(Azure.WaitUntil.Started, current.Value.Data, ct).ConfigureAwait(false);
        _logger.LogInformation("ACA revision swap initiated for {AcaAppName}.", acaAppName);
    }

    // ---- Host info ----------------------------------------------------------

    public Task<HostInfo> GetHostInfoAsync(CancellationToken ct = default)
    {
        var revision  = Environment.GetEnvironmentVariable("CONTAINER_APP_REVISION");
        var region    = Environment.GetEnvironmentVariable("CLOUDSMITH_AZURE_REGION");
        var rg        = Environment.GetEnvironmentVariable("CLOUDSMITH_ACA_RESOURCE_GROUP");
        return Task.FromResult(new HostInfo(revision ?? Environment.MachineName, region, rg));
    }

    // ---- Entra auto-create (AB#2412) ----------------------------------------

    /// <summary>
    /// Result type returned by <see cref="TryCreateEntraAppRegistrationAsync"/>.
    /// </summary>
    internal sealed record EntraAppResult(
        bool Success,
        string? ClientId,
        string? TenantId,
        string? ClientSecret,
        string? Error,
        string? ManualInstructions);

    /// <summary>
    /// AB#2412 — Provisions an Entra app registration via Microsoft Graph using the
    /// ACA Managed Identity (DefaultAzureCredential). The identity must hold the
    /// Entra <c>Application Administrator</c> role.
    ///
    /// On success returns (Success=true, ClientId, TenantId, ClientSecret, null, null).
    /// On permission failure returns (Success=false, …Error, ManualInstructions).
    ///
    /// TODO (wiring point): call this from SetupEndpoints when
    ///   CompleteSetupRequest.AutoCreateAppRegistration == true and substrate is PaaSAdapter.
    ///   Store the returned ClientId / TenantId / ClientSecret via SetSecretAsync and
    ///   record them in the platform_identity_providers table.
    /// </summary>
    /// <param name="portalFqdn">
    /// The public portal FQDN, e.g. "myplatform.azurecontainerapps.io".
    /// Used to populate the redirect URI as "https://{portalFqdn}/signin-oidc".
    /// </param>
    /// <param name="httpClientFactory">Injected IHttpClientFactory — uses the "graph" named client.</param>
    /// <param name="ct">Cancellation token.</param>
    internal async Task<EntraAppResult> TryCreateEntraAppRegistrationAsync(
        string portalFqdn,
        IHttpClientFactory httpClientFactory,
        CancellationToken ct = default)
    {
        // 1. Obtain a Microsoft Graph access token from the Managed Identity.
        string graphToken;
        string tenantId;
        try
        {
            var credential  = new DefaultAzureCredential();
            var tokenRequest = new TokenRequestContext(["https://graph.microsoft.com/.default"]);
            var tokenResult  = await credential.GetTokenAsync(tokenRequest, ct).ConfigureAwait(false);
            graphToken = tokenResult.Token;

            // Derive tenantId from the JWT payload (oid/tid claim) without a full JWT parser.
            // The tid claim is in the second base64url segment of the JWT.
            tenantId = ExtractTidFromJwt(graphToken)
                       ?? Environment.GetEnvironmentVariable("AZURE_TENANT_ID")
                       ?? string.Empty;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to obtain Microsoft Graph token from Managed Identity.");
            return new EntraAppResult(
                Success: false,
                ClientId: null,
                TenantId: null,
                ClientSecret: null,
                Error: $"Managed Identity could not acquire a Graph token: {ex.Message}",
                ManualInstructions: BuildManualInstructions(portalFqdn));
        }

        // Note: HttpClient from IHttpClientFactory is managed by the factory; do not dispose.
        var http = httpClientFactory.CreateClient("graph");
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", graphToken);

        // 2. POST /v1.0/applications — create the app registration.
        var redirectUri = $"https://{portalFqdn.TrimEnd('/')}/signin-oidc";
        var appBody = new
        {
            displayName    = "CloudSmith Portal",
            signInAudience = "AzureADMyOrg",
            web = new
            {
                redirectUris = new[] { redirectUri },
                implicitGrantSettings = new { enableIdTokenIssuance = true },
            },
            requiredResourceAccess = new[]
            {
                new
                {
                    resourceAppId = "00000003-0000-0000-c000-000000000000", // Microsoft Graph
                    resourceAccess = new[]
                    {
                        new { id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d", type = "Scope" }, // User.Read
                    },
                },
            },
        };

        string? appId;
        string? objectId;
        try
        {
            using var createResp = await http.PostAsync(
                "https://graph.microsoft.com/v1.0/applications",
                new StringContent(JsonSerializer.Serialize(appBody), Encoding.UTF8, "application/json"),
                ct).ConfigureAwait(false);

            if (!createResp.IsSuccessStatusCode)
            {
                var body = await createResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                var isPermission = (int)createResp.StatusCode is 401 or 403;
                _logger.LogWarning(
                    "Graph POST /applications returned {Status}: {Body}",
                    (int)createResp.StatusCode, TruncateLog(body, 400));

                return new EntraAppResult(
                    Success: false,
                    ClientId: null,
                    TenantId: null,
                    ClientSecret: null,
                    Error: isPermission
                        ? "The Managed Identity does not have the Entra Application Administrator role. " +
                          "Grant it in Azure AD Roles and re-run setup, or create the app registration manually."
                        : $"Graph returned {(int)createResp.StatusCode}: {TruncateLog(body, 200)}",
                    ManualInstructions: isPermission ? BuildManualInstructions(portalFqdn) : null);
            }

            using var appDoc = JsonDocument.Parse(
                await createResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            appId    = appDoc.RootElement.TryGetProperty("appId", out var appIdEl) ? appIdEl.GetString() : null;
            objectId = appDoc.RootElement.TryGetProperty("id", out var idEl)       ? idEl.GetString()    : null;

            if (string.IsNullOrEmpty(appId) || string.IsNullOrEmpty(objectId))
                return new EntraAppResult(false, null, null, null,
                    "Graph returned an application object without appId or id.", null);

            _logger.LogInformation(
                "Entra app registration created. AppId={AppId} ObjectId={ObjectId}", appId, objectId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Exception creating Entra app registration via Graph.");
            return new EntraAppResult(false, null, null, null,
                $"Graph application creation threw: {ex.Message}", BuildManualInstructions(portalFqdn));
        }

        // 3. POST /v1.0/applications/{objectId}/addPassword — create a client secret.
        string? secretValue;
        try
        {
            var addPasswordBody = new
            {
                passwordCredential = new
                {
                    displayName = "CloudSmith Portal Secret",
                    endDateTime = DateTime.UtcNow.AddYears(2).ToString("o"),
                },
            };

            using var secretResp = await http.PostAsync(
                $"https://graph.microsoft.com/v1.0/applications/{objectId}/addPassword",
                new StringContent(JsonSerializer.Serialize(addPasswordBody), Encoding.UTF8, "application/json"),
                ct).ConfigureAwait(false);

            if (!secretResp.IsSuccessStatusCode)
            {
                var body = await secretResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                _logger.LogWarning(
                    "Graph POST /addPassword returned {Status}: {Body}",
                    (int)secretResp.StatusCode, TruncateLog(body, 400));
                return new EntraAppResult(false, null, null, null,
                    $"Graph addPassword returned {(int)secretResp.StatusCode}: {TruncateLog(body, 200)}", null);
            }

            using var secretDoc = JsonDocument.Parse(
                await secretResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            secretValue = secretDoc.RootElement.TryGetProperty("secretText", out var stEl)
                ? stEl.GetString()
                : null;

            if (string.IsNullOrEmpty(secretValue))
                return new EntraAppResult(false, null, null, null,
                    "Graph addPassword response did not contain secretText.", null);

            _logger.LogInformation("Client secret created for Entra app {AppId}.", appId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Exception creating Entra client secret via Graph.");
            return new EntraAppResult(false, null, null, null,
                $"Graph addPassword threw: {ex.Message}", null);
        }

        return new EntraAppResult(
            Success: true,
            ClientId: appId,
            TenantId: tenantId,
            ClientSecret: secretValue,
            Error: null,
            ManualInstructions: null);
    }

    // ---- Helpers ------------------------------------------------------------

    /// <summary>
    /// Extracts the <c>tid</c> claim from a JWT access token without external dependencies.
    /// Returns null if the token is malformed.
    /// </summary>
    private static string? ExtractTidFromJwt(string jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length < 2) return null;

            // Pad to a valid base64url length.
            var payload = parts[1];
            var padded  = payload.Length % 4 switch
            {
                2 => payload + "==",
                3 => payload + "=",
                _ => payload,
            };
            padded = padded.Replace('-', '+').Replace('_', '/');

            using var doc = JsonDocument.Parse(Convert.FromBase64String(padded));
            return doc.RootElement.TryGetProperty("tid", out var tid) ? tid.GetString() : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Returns manual app-registration instructions for operators who don't have the
    /// Application Administrator role on their Managed Identity.
    /// </summary>
    private static string BuildManualInstructions(string portalFqdn)
    {
        var redirectUri = $"https://{portalFqdn.TrimEnd('/')}/signin-oidc";
        return $"""
            To create the Entra app registration manually:
            1. Open the Azure portal → Azure Active Directory → App registrations → New registration.
            2. Name: "CloudSmith Portal", Supported account types: "Accounts in this org only".
            3. Redirect URI (Web): {redirectUri}
            4. Under "Implicit grant and hybrid flows", enable "ID tokens".
            5. Under "API permissions", add Microsoft Graph → User.Read (Delegated).
            6. Create a client secret (Certificates & secrets → New client secret).
            7. Copy the Application (client) ID, Directory (tenant) ID, and secret value.
            8. Re-submit setup with autoCreateAppRegistration=false and provide those values.
            """;
    }

    private static string TruncateLog(string s, int max) =>
        s.Length > max ? s[..max] + "…" : s;
}
