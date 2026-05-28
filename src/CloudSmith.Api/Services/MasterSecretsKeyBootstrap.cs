// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CloudSmith.Api.Substrate;
using CloudSmith.Core.Substrate;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;

namespace CloudSmith.Api.Services;

/// <summary>
/// AB#1591 — Startup bootstrap for master encryption key and initial admin token.
///
/// On first startup (fresh database) this service:
///   1. Generates a 256-bit AES master secrets key and stores it outside the database:
///      - Standalone: written to /etc/cloudsmith/secrets.key (Linux, mode 600) or
///        %PROGRAMDATA%\CloudSmith\secrets.key (Windows, ACL-restricted to SYSTEM + service account).
///      - PaaS: read from the CLOUDSMITH_MASTER_KEY environment variable (injected by the
///        ACA Key Vault secret reference at deploy time — never touched by this service).
///      The DB row for key "master_secrets_key" stores only the sentinel "managed_externally"
///      so subsequent startups skip re-generation without revealing key material.
///   2. Checks whether any admin user exists. If none exists, generates a one-time initial
///      admin token (32 bytes of random hex) with a 30-minute TTL, writes the token to a
///      file (standalone) or the CLOUDSMITH_TOKEN_PATH env var path (PaaS), and persists
///      only its SHA-256 hash + expiry timestamp to <c>core.bootstrap_config</c>.
///      Emits an audit log row on issuance. On next startup with an un-consumed expired
///      token, emits an expiry audit log row.
///      <see cref="RevokeInitialAdminTokenAsync"/> must be called by SetupService when
///      setup completes to delete the hash row and emit the consumed audit row.
/// </summary>
public sealed class MasterSecretsKeyBootstrap : IHostedService
{
    private const string MasterKeyConfigKey      = "master_secrets_key";
    private const string InitialTokenHashKey     = "initial_admin_token_hash";
    private const string ManagedExternallySentinel = "managed_externally";

    // AB#2349 (ADR-047 amendment): TTL extended to 24h on both substrates.
    // The original 30-minute window was incompatible with the PaaS workflow
    // (azd/Bicep deploy + walk-away). 24h covers a normal "deploy in the morning,
    // complete setup in the afternoon" operator workflow on both PaaS and on-prem.
    private const int    TokenTtlMinutes         = 24 * 60;

    // PaaS: name of the Key Vault secret that holds the plaintext initial admin token.
    // ADR-047 OQ-047-B resolution (2026-05-27): operator retrieves with
    //   az keyvault secret show --vault-name <kv> --name cloudsmith-initial-admin-token --query value -o tsv
    private const string InitialTokenSecretName  = "cloudsmith-initial-admin-token";

    // Secret name used when storing the master key file on standalone deployments.
    private static readonly string MasterKeyFilePath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CloudSmith", "secrets.key")
        : "/etc/cloudsmith/secrets.key";

    private readonly NpgsqlDataSource _db;
    private readonly ILogger<MasterSecretsKeyBootstrap> _logger;
    private readonly ISubstrateAdapter _substrate;

    public MasterSecretsKeyBootstrap(NpgsqlDataSource db, ILogger<MasterSecretsKeyBootstrap> logger, ISubstrateAdapter substrate)
    {
        _db        = db;
        _logger    = logger;
        _substrate = substrate;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // CLOUDSMITH_SKIP_MIGRATIONS=true signals a no-DB environment (e.g. OpenAPI spec generation
        // in CI). Skip all DB operations to allow the app to start without a PostgreSQL connection.
        if (string.Equals(
                Environment.GetEnvironmentVariable("CLOUDSMITH_SKIP_MIGRATIONS"),
                "true",
                StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("MasterSecretsKeyBootstrap: skipping startup (CLOUDSMITH_SKIP_MIGRATIONS=true).");
            return;
        }

        await EnsureMasterSecretsKeyAsync(cancellationToken);
        await EnsureInitialAdminTokenAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    // -------------------------------------------------------------------------
    // Master secrets key — 256-bit AES key stored outside the database (C1 fix)
    // -------------------------------------------------------------------------

    private async Task EnsureMasterSecretsKeyAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenConnectionAsync(ct);

        // A sentinel row means the key was already bootstrapped (or is PaaS-managed).
        var existing = await GetConfigValueAsync(conn, MasterKeyConfigKey, ct);
        if (existing is not null)
        {
            _logger.LogDebug("Master secrets key already bootstrapped; skipping generation.");
            return;
        }

        if (_substrate.Mode == SubstrateMode.PaaS)
        {
            // PaaS: key material must be injected via CLOUDSMITH_MASTER_KEY env var
            // (ACA Key Vault secret reference). Validate it is present and non-empty.
            var kvKey = Environment.GetEnvironmentVariable("CLOUDSMITH_MASTER_KEY");
            if (string.IsNullOrWhiteSpace(kvKey))
            {
                _logger.LogError(
                    "PaaS deployment detected but CLOUDSMITH_MASTER_KEY env var is missing. " +
                    "Configure a Key Vault secret reference named 'cloudsmith-master-key' on the ACA app.");
                throw new InvalidOperationException(
                    "CLOUDSMITH_MASTER_KEY is required in PaaS mode. " +
                    "Add a Key Vault secret reference to the Container App.");
            }

            // Only write the sentinel — key material stays in Key Vault / env var.
            await UpsertConfigValueAsync(conn, MasterKeyConfigKey, ManagedExternallySentinel, null, ct);
            _logger.LogInformation(
                "PaaS master secrets key validated from CLOUDSMITH_MASTER_KEY env var. " +
                "Sentinel stored in core.bootstrap_config — key material is never persisted to the database.");
        }
        else
        {
            // Standalone: generate 256-bit AES key and write to a restricted file.
            var keyBytes  = RandomNumberGenerator.GetBytes(32);
            var keyBase64 = Convert.ToBase64String(keyBytes);

            WriteKeyFile(MasterKeyFilePath, keyBase64);

            // Store only the sentinel — not the key material — in the database.
            await UpsertConfigValueAsync(conn, MasterKeyConfigKey, ManagedExternallySentinel, null, ct);
            _logger.LogInformation(
                "Master secrets key generated and written to {KeyFilePath} (mode 600). " +
                "The database stores only a sentinel value — key material is never persisted to the database.",
                MasterKeyFilePath);
        }
    }

    /// <summary>
    /// Writes <paramref name="content"/> to <paramref name="filePath"/> with
    /// owner-only read/write permissions (equivalent to chmod 600 on Linux).
    /// </summary>
    private static void WriteKeyFile(string filePath, string content)
    {
        var dir = Path.GetDirectoryName(filePath)!;
        Directory.CreateDirectory(dir);

        // Write the file; we will restrict permissions immediately after.
        File.WriteAllText(filePath, content);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Restrict to SYSTEM + the current user (service account) only.
            // Remove inherited permissions, then grant Modify to current user and SYSTEM.
            var acl  = new System.Security.AccessControl.FileSecurity();
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
            // Linux / macOS: chmod 600 — owner read/write only, no group or other.
            const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            File.SetUnixFileMode(filePath, ownerOnly);
        }
    }

    // -------------------------------------------------------------------------
    // Initial admin token — written to file with 30-min TTL (C2 fix)
    // -------------------------------------------------------------------------

    private async Task EnsureInitialAdminTokenAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenConnectionAsync(ct);

        // If the hash row already exists, the token was either already issued or consumed.
        var (existingHash, expiresAt) = await GetConfigValueWithExpiryAsync(conn, InitialTokenHashKey, ct);
        if (existingHash is not null)
        {
            // Check if an un-consumed token has already expired.
            if (expiresAt.HasValue && DateTimeOffset.UtcNow > expiresAt.Value)
            {
                // Emit expiry audit row and remove the stale hash.
                await AppendAuditRowAsync(conn, "initial_admin_token_expired",
                    afterJson: $"{{\"expired_at\":\"{expiresAt.Value:o}\"}}", ct);
                await using var delCmd = conn.CreateCommand();
                delCmd.CommandText = "DELETE FROM core.bootstrap_config WHERE key = @key";
                delCmd.Parameters.AddWithValue("key", InitialTokenHashKey);
                await delCmd.ExecuteNonQueryAsync(ct);
                _logger.LogWarning("Initial admin token expired without use and has been purged. Restart the service to generate a fresh token.");
            }
            else
            {
                _logger.LogDebug("Initial admin token hash already exists and has not expired; skipping token generation.");
            }
            return;
        }

        // Only generate a token if setup is not yet complete.
        var setupComplete = await IsSetupCompleteAsync(conn, ct);
        if (setupComplete)
        {
            _logger.LogDebug("Setup is already complete; no initial admin token needed.");
            return;
        }

        // Generate 32 bytes of cryptographic randomness, format as lowercase hex.
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token      = Convert.ToHexString(tokenBytes).ToLowerInvariant();

        // 30-minute TTL.
        var expiry = DateTimeOffset.UtcNow.AddMinutes(TokenTtlMinutes);

        // Persist SHA-256 hash + expiry — plaintext token never touches the database.
        var hashBytes  = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token));
        var tokenHash  = Convert.ToBase64String(hashBytes);

        await UpsertConfigValueAsync(conn, InitialTokenHashKey, tokenHash, expiry, ct);

        // Emit issuance audit row.
        await AppendAuditRowAsync(conn, "initial_admin_token_issued",
            afterJson: $"{{\"expires_at\":\"{expiry:o}\"}}", ct);

        // AB#2350 — delegate write to the substrate adapter with TTL (PaaS → KV secret with 24h expiry; on-prem → restricted file).
        await _substrate.WriteOperatorArtifactAsync(InitialTokenSecretName, token, ArtifactKind.Secret, expiry, ct);

        // Only the retrieval hint goes to stdout — never the token value itself.
        Console.WriteLine($"[CloudSmith] Initial admin token written. Retrieve with: {_substrate.GetOperatorRetrievalHint(InitialTokenSecretName)}");

        _logger.LogWarning(
            "Initial admin token written (expires {ExpiresAt:o}). " +
            "Retrieve with: {RetrievalHint}. Complete first-run setup within {TtlHours} hours.",
            expiry,
            _substrate.GetOperatorRetrievalHint(InitialTokenSecretName),
            TokenTtlMinutes / 60);
    }

    // -------------------------------------------------------------------------
    // Master key accessor — canonical source for all encryption operations
    // -------------------------------------------------------------------------

    /// <summary>
    /// Loads the master key bytes from the canonical source:
    /// PaaS → <c>CLOUDSMITH_MASTER_KEY</c> env var; standalone → key file.
    /// Returns <see langword="null"/> if the key is unavailable.
    /// All components that need the master key must use this method rather than
    /// re-implementing key loading independently.
    /// </summary>
    public byte[]? LoadMasterKey()
    {
        // PaaS: CLOUDSMITH_MASTER_KEY env var contains the raw base64 key.
        var envKey = Environment.GetEnvironmentVariable("CLOUDSMITH_MASTER_KEY");
        if (!string.IsNullOrWhiteSpace(envKey))
        {
            try { return Convert.FromBase64String(envKey); }
            catch { /* fall through to file */ }
        }

        // Standalone: read from the key file.
        if (!File.Exists(MasterKeyFilePath)) return null;
        try
        {
            var keyBase64 = File.ReadAllText(MasterKeyFilePath).Trim();
            return Convert.FromBase64String(keyBase64);
        }
        catch
        {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Token revocation — called by SetupService on setup completion
    // -------------------------------------------------------------------------

    /// <summary>
    /// Revokes the initial admin token by deleting its hash from bootstrap_config.
    /// Called after first-run setup completes so the one-time token can never be reused.
    /// Emits a consumption audit row.
    /// </summary>
    public async Task RevokeInitialAdminTokenAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenConnectionAsync(ct);
        await AppendAuditRowAsync(conn, "initial_admin_token_consumed", afterJson: null, ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM core.bootstrap_config WHERE key = @key";
        cmd.Parameters.AddWithValue("key", InitialTokenHashKey);
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0)
            _logger.LogInformation("Initial admin token revoked after setup completion.");
    }

    // -------------------------------------------------------------------------
    // Token validation — called by SetupEndpoints to verify the one-time token
    // -------------------------------------------------------------------------

    /// <summary>
    /// Validates the supplied token against the stored hash.
    /// Returns <see langword="false"/> if the token is unknown, already consumed, or past its expiry.
    /// </summary>
    public async Task<TokenValidationResult> ValidateInitialAdminTokenAsync(string token, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenConnectionAsync(ct);
        var (storedHash, expiresAt) = await GetConfigValueWithExpiryAsync(conn, InitialTokenHashKey, ct);
        if (storedHash is null)
            return TokenValidationResult.NotFound;

        if (expiresAt.HasValue && DateTimeOffset.UtcNow > expiresAt.Value)
            return TokenValidationResult.Expired;

        var hashBytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token));
        var supplied  = Convert.ToBase64String(hashBytes);
        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(supplied),
            System.Text.Encoding.UTF8.GetBytes(storedHash))
            ? TokenValidationResult.Valid
            : TokenValidationResult.Invalid;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static async Task<string?> GetConfigValueAsync(NpgsqlConnection conn, string key, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM core.bootstrap_config WHERE key = @key LIMIT 1";
        cmd.Parameters.AddWithValue("key", key);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is DBNull or null ? null : (string)result;
    }

    private static async Task<(string? Value, DateTimeOffset? ExpiresAt)> GetConfigValueWithExpiryAsync(
        NpgsqlConnection conn, string key, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value, expires_at FROM core.bootstrap_config WHERE key = @key LIMIT 1";
        cmd.Parameters.AddWithValue("key", key);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return (null, null);
        var value    = reader.GetString(0);
        var expiry   = reader.IsDBNull(1) ? (DateTimeOffset?)null
                     : new DateTimeOffset(reader.GetDateTime(1), TimeSpan.Zero);
        return (value, expiry);
    }

    private static async Task UpsertConfigValueAsync(
        NpgsqlConnection conn, string key, string value, DateTimeOffset? expiresAt, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO core.bootstrap_config (key, value, expires_at)
            VALUES (@key, @value, @expires_at)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
            """;
        cmd.Parameters.AddWithValue("key", key);
        cmd.Parameters.AddWithValue("value", value);
        var p = new NpgsqlParameter("expires_at", NpgsqlDbType.TimestampTz);
        p.Value = expiresAt.HasValue ? (object)expiresAt.Value.UtcDateTime : DBNull.Value;
        cmd.Parameters.Add(p);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task<bool> IsSetupCompleteAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT setup_state FROM core.platform_setup WHERE id = true LIMIT 1";
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is string state && state == "Completed";
    }

    /// <summary>
    /// Appends a row to <c>core.audit_log</c> for bootstrap security events.
    /// Uses a nil org_id (all-zeros UUID) as a sentinel for system-level events that
    /// predate any org context — these rows are excluded from the tenant-scoped audit query.
    /// </summary>
    private static async Task AppendAuditRowAsync(
        NpgsqlConnection conn, string action, string? afterJson, CancellationToken ct)
    {
        try
        {
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO core.audit_log
                    (org_id, user_id, action, resource_type, resource_id, after_json, occurred_at)
                VALUES
                    ('00000000-0000-0000-0000-000000000000', NULL, @action, 'bootstrap', NULL, @after_json::jsonb, now())
                """;
            cmd.Parameters.AddWithValue("action", action);
            var afterParam = new NpgsqlParameter("after_json", NpgsqlDbType.Text);
            afterParam.Value = afterJson is not null ? (object)afterJson : DBNull.Value;
            cmd.Parameters.Add(afterParam);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch
        {
            // Audit writes are best-effort during bootstrap — never let a log failure
            // prevent the service from starting.
        }
    }
}

/// <summary>Result codes for <see cref="MasterSecretsKeyBootstrap.ValidateInitialAdminTokenAsync"/>.</summary>
public enum TokenValidationResult
{
    Valid,
    Invalid,
    NotFound,
    Expired,
}
