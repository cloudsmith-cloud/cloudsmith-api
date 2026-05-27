// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace CloudSmith.Api.Services;

/// <summary>
/// AB#1591 — Startup bootstrap for master encryption key and initial admin token.
///
/// On first startup (fresh database) this service:
///   1. Generates a 256-bit AES master secrets key and persists it to
///      <c>core.bootstrap_config</c> under key <c>master_secrets_key</c>.
///      Subsequent startups find the key already present and skip generation.
///   2. Checks whether any admin user exists. If none exists, generates a
///      one-time initial admin token (32 bytes of random hex), prints it to
///      stdout as <c>[CloudSmith] Initial admin token: &lt;token&gt;</c> (visible
///      in container logs), and persists its SHA-256 hash to
///      <c>core.bootstrap_config</c> under key <c>initial_admin_token_hash</c>.
///      Once setup is completed the hash row is deleted by
///      <see cref="SetupCompletedTokenRevocation"/> so the token cannot be reused.
/// </summary>
public sealed class MasterSecretsKeyBootstrap : IHostedService
{
    private const string MasterKeyConfigKey = "master_secrets_key";
    private const string InitialTokenHashKey = "initial_admin_token_hash";

    private readonly NpgsqlDataSource _db;
    private readonly ILogger<MasterSecretsKeyBootstrap> _logger;

    public MasterSecretsKeyBootstrap(NpgsqlDataSource db, ILogger<MasterSecretsKeyBootstrap> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await EnsureMasterSecretsKeyAsync(cancellationToken);
        await EnsureInitialAdminTokenAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    // -------------------------------------------------------------------------
    // Master secrets key — 256-bit AES key, base64-encoded, persisted once
    // -------------------------------------------------------------------------

    private async Task EnsureMasterSecretsKeyAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenConnectionAsync(ct);

        // Check if the key already exists
        var existing = await GetConfigValueAsync(conn, MasterKeyConfigKey, ct);
        if (existing is not null)
        {
            _logger.LogDebug("Master secrets key already exists; skipping generation.");
            return;
        }

        // Generate 256-bit (32-byte) AES key
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        var keyBase64 = Convert.ToBase64String(keyBytes);

        await UpsertConfigValueAsync(conn, MasterKeyConfigKey, keyBase64, ct);
        _logger.LogInformation("Master secrets key generated and persisted to core.bootstrap_config.");
    }

    // -------------------------------------------------------------------------
    // Initial admin token — one-time token printed to stdout on first run
    // -------------------------------------------------------------------------

    private async Task EnsureInitialAdminTokenAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenConnectionAsync(ct);

        // If the hash row already exists the token was already issued (or revoked).
        var existingHash = await GetConfigValueAsync(conn, InitialTokenHashKey, ct);
        if (existingHash is not null)
        {
            _logger.LogDebug("Initial admin token hash already exists; skipping token generation.");
            return;
        }

        // Only generate a token if setup is not yet complete (no admin user exists).
        var setupComplete = await IsSetupCompleteAsync(conn, ct);
        if (setupComplete)
        {
            _logger.LogDebug("Setup is already complete; no initial admin token needed.");
            return;
        }

        // Generate 32 bytes of cryptographic randomness, format as lowercase hex.
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToHexString(tokenBytes).ToLowerInvariant();

        // Persist the SHA-256 hash so the token can only be used once and the
        // plaintext never touches the database.
        var hashBytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token));
        var tokenHash = Convert.ToBase64String(hashBytes);

        await UpsertConfigValueAsync(conn, InitialTokenHashKey, tokenHash, ct);

        // Print plaintext token to stdout — visible in container / service logs.
        Console.WriteLine($"[CloudSmith] Initial admin token: {token}");
        _logger.LogWarning("Initial admin token printed to stdout. Complete first-run setup to revoke it.");
    }

    // -------------------------------------------------------------------------
    // Token revocation — called by SetupService on setup completion
    // -------------------------------------------------------------------------

    /// <summary>
    /// Revokes the initial admin token by deleting its hash from bootstrap_config.
    /// Called after first-run setup completes so the one-time token can never be reused.
    /// </summary>
    public async Task RevokeInitialAdminTokenAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM core.bootstrap_config WHERE key = @key";
        cmd.Parameters.AddWithValue("key", InitialTokenHashKey);
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0)
            _logger.LogInformation("Initial admin token revoked after setup completion.");
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

    private static async Task UpsertConfigValueAsync(NpgsqlConnection conn, string key, string value, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO core.bootstrap_config (key, value)
            VALUES (@key, @value)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """;
        cmd.Parameters.AddWithValue("key", key);
        cmd.Parameters.AddWithValue("value", value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task<bool> IsSetupCompleteAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT setup_state FROM core.platform_setup WHERE id = true LIMIT 1";
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is string state && state == "Completed";
    }
}
