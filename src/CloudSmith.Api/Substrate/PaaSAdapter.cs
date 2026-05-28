// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Azure;
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

    public async Task WriteOperatorArtifactAsync(string logicalName, string content, ArtifactKind kind, CancellationToken ct = default)
    {
        // All artifact kinds on PaaS go to KV with a kind tag.
        var secret = new KeyVaultSecret(logicalName, content)
        {
            Properties =
            {
                ContentType = "text/plain",
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

        var armClient = new ArmClient(new DefaultAzureCredential());
        var appId     = ContainerAppResource.CreateResourceIdentifier(subscriptionId, resourceGroup, "ca-cloudsmith-api");
        var apiApp    = armClient.GetContainerAppResource(appId);
        var current   = await apiApp.GetAsync(ct).ConfigureAwait(false);

        await apiApp.UpdateAsync(Azure.WaitUntil.Started, current.Value.Data, ct).ConfigureAwait(false);
        _logger.LogInformation("ACA revision swap initiated for ca-cloudsmith-api.");
    }

    // ---- Host info ----------------------------------------------------------

    public Task<HostInfo> GetHostInfoAsync(CancellationToken ct = default)
    {
        var revision  = Environment.GetEnvironmentVariable("CONTAINER_APP_REVISION");
        var region    = Environment.GetEnvironmentVariable("CLOUDSMITH_AZURE_REGION");
        var rg        = Environment.GetEnvironmentVariable("CLOUDSMITH_ACA_RESOURCE_GROUP");
        return Task.FromResult(new HostInfo(revision ?? Environment.MachineName, region, rg));
    }
}
