// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Runtime.InteropServices;
using CloudSmith.Api.Hubs;
using CloudSmith.Core.Substrate;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging;

namespace CloudSmith.Api.Substrate;

/// <summary>
/// AB#2354 — On-premises (Docker Compose / Appliance) substrate adapter.
/// Secrets → restricted files under /etc/cloudsmith/secrets/ (Linux) or %PROGRAMDATA%\CloudSmith\secrets\ (Windows).
/// Image update → SignalR broadcast to runner agents in the "platform:runners" group.
/// </summary>
internal sealed class OnPremAdapter : ISubstrateAdapter
{
    private static readonly string SecretsDir = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CloudSmith", "secrets")
        : "/etc/cloudsmith/secrets";

    private static readonly string ReceiptsDir = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CloudSmith", "receipts")
        : "/var/lib/cloudsmith/receipts";

    private readonly IHubContext<PlatformHub> _hub;
    private readonly ILogger<OnPremAdapter> _logger;

    public SubstrateMode Mode => SubstrateMode.OnPrem;

    public OnPremAdapter(IHubContext<PlatformHub> hub, ILogger<OnPremAdapter> logger)
    {
        _hub    = hub;
        _logger = logger;
    }

    // ---- Secrets ------------------------------------------------------------

    public Task<string?> GetSecretAsync(string name, CancellationToken ct = default)
    {
        var path = SecretPath(name);
        if (!File.Exists(path))
            return Task.FromResult<string?>(null);

        try
        {
            return Task.FromResult<string?>(File.ReadAllText(path).Trim());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read secret '{Name}' from {Path}.", name, path);
            return Task.FromResult<string?>(null);
        }
    }

    public Task SetSecretAsync(string name, string value, DateTimeOffset? expiresOn = null, CancellationToken ct = default)
    {
        WriteRestrictedFile(SecretPath(name), value);
        return Task.CompletedTask;
    }

    public Task DeleteSecretAsync(string name, CancellationToken ct = default)
    {
        var path = SecretPath(name);
        if (File.Exists(path))
            File.Delete(path);
        return Task.CompletedTask;
    }

    // ---- Operator artifacts -------------------------------------------------

    public Task WriteOperatorArtifactAsync(string logicalName, string content, ArtifactKind kind, CancellationToken ct = default)
    {
        switch (kind)
        {
            case ArtifactKind.Secret:
                WriteRestrictedFile(SecretPath(logicalName), content);
                _logger.LogInformation("Operator artifact '{LogicalName}' (kind=Secret) written to {Path}.", logicalName, SecretPath(logicalName));
                break;

            case ArtifactKind.Receipt:
                var receiptPath = Path.Combine(ReceiptsDir, $"{logicalName}.txt");
                Directory.CreateDirectory(ReceiptsDir);
                File.WriteAllText(receiptPath, content);
                _logger.LogInformation("Operator artifact '{LogicalName}' (kind=Receipt) written to {Path}.", logicalName, receiptPath);
                break;

            case ArtifactKind.Diagnostic:
                _logger.LogInformation("Operator artifact '{LogicalName}' (kind=Diagnostic): {Content}", logicalName, content);
                break;
        }

        return Task.CompletedTask;
    }

    public string GetOperatorRetrievalHint(string logicalName)
    {
        var path = SecretPath(logicalName);
        return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? $"Get-Content \"{path}\""
            : $"cat {path}";
    }

    // ---- Platform lifecycle -------------------------------------------------

    public async Task TriggerImageUpdateAsync(string imageRef, CancellationToken ct = default)
    {
        var updateId = Guid.NewGuid();
        await _hub.Clients
            .Group("platform:runners")
            .SendAsync("platform:update", new { updateId, requestedAt = DateTimeOffset.UtcNow }, ct)
            .ConfigureAwait(false);

        _logger.LogInformation(
            "Platform update dispatched to on-prem runner group. UpdateId={UpdateId}", updateId);
    }

    // ---- Host info ----------------------------------------------------------

    public Task<HostInfo> GetHostInfoAsync(CancellationToken ct = default) =>
        Task.FromResult(new HostInfo(Environment.MachineName, null, null));

    // ---- Helpers ------------------------------------------------------------

    private static string SecretPath(string name) =>
        Path.Combine(SecretsDir, $"{name}.txt");

    /// <summary>
    /// Writes <paramref name="content"/> to <paramref name="filePath"/> with
    /// owner-only read/write permissions (equivalent to chmod 600 on Linux).
    /// </summary>
    private static void WriteRestrictedFile(string filePath, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, content);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var acl = new System.Security.AccessControl.FileSecurity();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                Environment.UserName,
                System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.Write,
                System.Security.AccessControl.AccessControlType.Allow));
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                @"NT AUTHORITY\SYSTEM",
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(filePath).SetAccessControl(acl);
        }
        else
        {
            const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            File.SetUnixFileMode(filePath, ownerOnly);
        }
    }
}
