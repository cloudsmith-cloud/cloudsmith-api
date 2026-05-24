// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Buffers;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CloudSmith.Api.Authorization;
using CloudSmith.Api.Relay;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Relay bridge endpoints (AB#1670). The cloudsmith-relay agent runs on-prem,
/// holds an identity certificate, and pushes inventory/health into the PaaS
/// from the customer side. The PaaS side never reaches into the customer network.
///
/// Enrollment flow:
///  1. Operator (PlatformAdmin / OrgAdmin) calls POST /api/v1/relays/enroll-token
///     with a display name and gets back a 1-hour plaintext token + expiry.
///  2. Operator pastes the token into the Relay installer. The Relay generates
///     a keypair locally and calls POST /api/v1/relays/enroll with
///     { token, displayName, publicKeyPem }. The PaaS validates the SHA-256
///     hash of the token against core.relay_enrollment_tokens, marks the token
///     consumed, and inserts a row in core.relays.
///  3. The Relay subsequently calls /api/v1/clusters, /api/v1/inventory/ingest
///     and /api/v1/health/probe-result on a schedule.
///
/// Endpoint summary:
///   POST   /api/v1/relays/enroll-token        platform:write    issue 1h enrollment token
///   POST   /api/v1/relays/enroll              (anonymous)       Relay first-call — token is the credential
///   GET    /api/v1/relays                     platform:read     list relays for the caller's org
///   GET    /api/v1/relays/{relayId}           platform:read     detail
///   DELETE /api/v1/relays/{relayId}           platform:write    revoke (status='revoked')
///   GET    /api/v1/relays/{relayId}/connect   (relay-identity)  persistent WebSocket hub (AB#1679)
///   POST   /api/v1/clusters                   platform:write    register cluster (relay or operator)
///   POST   /api/v1/inventory/ingest           inventory:write   Relay pushes a batch of VM rows
///   POST   /api/v1/health/probe-result        monitoring:write  Relay pushes a cluster health probe
/// </summary>
public static class RelayEndpoints
{
    private static readonly HashSet<string> AllowedClusterTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "HyperV", "AzureLocal", "WSFC",
    };

    private static readonly HashSet<string> AllowedHealthStatuses = new(StringComparer.OrdinalIgnoreCase)
    {
        "healthy", "warning", "critical", "unknown", "online", "offline", "degraded",
    };

    public sealed record IssueEnrollmentTokenRequest(string DisplayName, Guid? SiteId);

    public sealed record IssueEnrollmentTokenResponse(string Token, string ExpiresAt, Guid TokenId);

    public sealed record EnrollRelayRequest(string Token, string DisplayName, string PublicKeyPem);

    public sealed record EnrollRelayResponse(Guid RelayId, string Certificate);

    public sealed record RelayResponse(
        Guid RelayId,
        Guid OrgId,
        Guid? SiteId,
        string DisplayName,
        string Status,
        string EnrolledAt,
        string? LastSeenAt);

    public sealed record RegisterClusterRequest(string Name, Guid? SiteId, string ClusterType, Guid? RelayId);

    public sealed record RegisterClusterResponse(Guid ClusterId);

    public sealed record InventoryItem(
        Guid ClusterId,
        Guid? VmId,
        string? VmGuid,
        string Name,
        string? State,
        int? CpuCount,
        long? MemoryMb);

    public sealed record InventoryIngestResponse(int Inserted, int Updated);

    public sealed record HealthProbeRequest(Guid ClusterId, string Status, JsonElement? Checks);

    public static IEndpointRouteBuilder MapRelayEndpoints(this IEndpointRouteBuilder app)
    {
        var relays = app.MapGroup("/api/v1/relays").WithTags("Relays");

        // POST /api/v1/relays/enroll-token — issue a 1-hour enrollment token.
        relays.MapPost("/enroll-token", async (
            IssueEnrollmentTokenRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
                return orgError!;
            if (!TryGetUserId(ctx, out var userId, out var userError))
                return userError!;

            if (string.IsNullOrWhiteSpace(req.DisplayName))
            {
                return Results.Json(
                    new { error = "invalid-request", message = "displayName is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            // Generate a 256-bit random token, base64url-encoded. Only the SHA-256
            // hash of the token is persisted — the plaintext is returned once and
            // never re-derivable from the database.
            var rawToken = RandomNumberGenerator.GetBytes(32);
            var token = Base64UrlEncode(rawToken);
            var tokenHash = ComputeSha256Hex(token);
            var expiresAt = DateTime.UtcNow.AddHours(1);

            const string sql = """
                INSERT INTO core.relay_enrollment_tokens
                    (org_id, token_hash, issued_by_user_id, expires_at)
                VALUES
                    (@org_id, @token_hash, @issued_by, @expires_at)
                RETURNING token_id, expires_at
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@token_hash", tokenHash);
            cmd.Parameters.AddWithValue("@issued_by", userId);
            cmd.Parameters.AddWithValue("@expires_at", expiresAt);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                return Results.Json(new { error = "insert-failed" }, statusCode: StatusCodes.Status500InternalServerError);
            }
            var tokenId = reader.GetGuid(0);
            var expires = reader.GetDateTime(1);

            // siteId is captured at issue time as a hint to the operator — the actual
            // Relay row records site_id on enroll, but the Relay does not see the
            // operator-issued site preference. For MVP we simply return the token.
            // displayName + siteId are echoed back via the portal UI flow.
            _ = req.SiteId; // intentionally unused at this layer for MVP

            return Results.Ok(new IssueEnrollmentTokenResponse(
                Token: token,
                ExpiresAt: expires.ToString("o"),
                TokenId: tokenId));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Issue a 1-hour Relay enrollment token (plaintext returned once; only SHA-256 stored).");

        // POST /api/v1/relays/enroll — anonymous; the token IS the credential.
        // Validates the token, inserts a relays row, marks the token consumed.
        relays.MapPost("/enroll", async (
            EnrollRelayRequest req,
            NpgsqlDataSource db,
            CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(req.Token)
                || string.IsNullOrWhiteSpace(req.DisplayName)
                || string.IsNullOrWhiteSpace(req.PublicKeyPem))
            {
                return Results.Json(
                    new { error = "invalid-request", message = "token, displayName, and publicKeyPem are required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var tokenHash = ComputeSha256Hex(req.Token);

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var tx = await conn.BeginTransactionAsync(ct);

            // Look up the enrollment token. Atomic: select-for-update so two Relays
            // racing the same token cannot both succeed.
            Guid orgId;
            Guid tokenId;
            await using (var lookup = new NpgsqlCommand("""
                SELECT token_id, org_id, expires_at, consumed_at
                FROM core.relay_enrollment_tokens
                WHERE token_hash = @token_hash
                FOR UPDATE
                """, conn, tx))
            {
                lookup.Parameters.AddWithValue("@token_hash", tokenHash);
                await using var reader = await lookup.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.Json(
                        new { error = "invalid-token", message = "Enrollment token not recognised." },
                        statusCode: StatusCodes.Status401Unauthorized);
                }
                tokenId = reader.GetGuid(0);
                orgId = reader.GetGuid(1);
                var expiresAt = reader.GetDateTime(2);
                var consumedAt = reader.IsDBNull(3) ? (DateTime?)null : reader.GetDateTime(3);

                if (consumedAt is not null)
                {
                    return Results.Json(
                        new { error = "token-already-consumed" },
                        statusCode: StatusCodes.Status401Unauthorized);
                }
                if (expiresAt < DateTime.UtcNow)
                {
                    return Results.Json(
                        new { error = "token-expired" },
                        statusCode: StatusCodes.Status401Unauthorized);
                }
            }

            // Insert the relay row.
            Guid relayId;
            try
            {
                await using var insert = new NpgsqlCommand("""
                    INSERT INTO core.relays
                        (org_id, display_name, public_key_pem)
                    VALUES
                        (@org_id, @display_name, @public_key_pem)
                    RETURNING relay_id
                    """, conn, tx);
                insert.Parameters.AddWithValue("@org_id", orgId);
                insert.Parameters.AddWithValue("@display_name", req.DisplayName);
                insert.Parameters.AddWithValue("@public_key_pem", req.PublicKeyPem);
                var result = await insert.ExecuteScalarAsync(ct);
                relayId = (Guid)result!;
            }
            catch (PostgresException pex) when (pex.SqlState == "23505")
            {
                return Results.Json(
                    new { error = "duplicate-display-name", message = "A relay with that display name already exists for this org." },
                    statusCode: StatusCodes.Status409Conflict);
            }

            // Mark the token consumed.
            await using (var consume = new NpgsqlCommand("""
                UPDATE core.relay_enrollment_tokens
                SET consumed_at = now(), consumed_by_relay_id = @relay_id
                WHERE token_id = @token_id
                """, conn, tx))
            {
                consume.Parameters.AddWithValue("@token_id", tokenId);
                consume.Parameters.AddWithValue("@relay_id", relayId);
                await consume.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);

            // MVP: echo the Relay's own public key back as the "certificate". Real
            // cert issuance is a follow-up via cloudsmith-identity (AB#TBD).
            return Results.Ok(new EnrollRelayResponse(
                RelayId: relayId,
                Certificate: req.PublicKeyPem));
        })
        .AllowAnonymous()
        .WithSummary("Relay first call — exchange a one-time enrollment token for a relay registration.");

        // GET /api/v1/relays — list relays for the caller's org.
        relays.MapGet("/", async (
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
                return orgError!;

            const string sql = """
                SELECT relay_id, org_id, site_id, display_name, status, enrolled_at, last_seen_at
                FROM core.relays
                WHERE org_id = @org_id
                ORDER BY display_name
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);

            var results = new List<RelayResponse>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                results.Add(ReadRelay(reader));
            }
            return Results.Ok(results);
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("List relays for the caller's organisation.");

        // GET /api/v1/relays/{relayId} — detail.
        relays.MapGet("/{relayId:guid}", async (
            Guid relayId,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
                return orgError!;

            const string sql = """
                SELECT relay_id, org_id, site_id, display_name, status, enrolled_at, last_seen_at
                FROM core.relays
                WHERE org_id = @org_id AND relay_id = @relay_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@relay_id", relayId);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                return Results.NotFound(new { error = "relay-not-found", relayId });
            }
            return Results.Ok(ReadRelay(reader));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:read")))
        .WithSummary("Get a relay by id.");

        // DELETE /api/v1/relays/{relayId} — soft-delete (status='revoked'); preserves audit trail.
        relays.MapDelete("/{relayId:guid}", async (
            Guid relayId,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
                return orgError!;

            const string sql = """
                UPDATE core.relays
                SET status = 'revoked'
                WHERE org_id = @org_id AND relay_id = @relay_id
                RETURNING relay_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@relay_id", relayId);

            var result = await cmd.ExecuteScalarAsync(ct);
            if (result is null || result is DBNull)
            {
                return Results.NotFound(new { error = "relay-not-found", relayId });
            }
            return Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Revoke a relay (status='revoked'); preserves audit trail.");

        // GET /api/v1/relays/{relayId}/connect — persistent WebSocket hub (AB#1679).
        // The Relay calls this after enrollment to establish the persistent data-plane
        // channel. Auth: X-CloudSmith-RelayId header must match the {relayId} path
        // segment, and the relay must exist in core.relays with status != 'revoked'.
        // Inbound frame dispatch:
        //   inventory.push  → upsert inventory.virtual_machines (delegates to ingest logic)
        //   health.push     → update cluster_mgmt.clusters.status
        //   heartbeat       → update core.relays.last_seen_at
        //   job.ack         → logged; no persistent action for MVP
        relays.MapGet("/{relayId:guid}/connect", async (
            Guid relayId,
            HttpContext ctx,
            NpgsqlDataSource db,
            IConnectedRelayRegistry registry,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            if (!ctx.WebSockets.IsWebSocketRequest)
            {
                return Results.Json(
                    new { error = "websocket-required", message = "This endpoint only accepts WebSocket upgrade requests." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            // Authenticate: X-CloudSmith-RelayId header must match relayId path param.
            var headerRelayId = ctx.Request.Headers["X-CloudSmith-RelayId"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(headerRelayId)
                || !Guid.TryParse(headerRelayId, out var headerGuid)
                || headerGuid != relayId)
            {
                return Results.Json(
                    new { error = "relay-identity-mismatch", message = "X-CloudSmith-RelayId header is missing or does not match the path relayId." },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            // Verify relay exists and is not revoked.
            Guid orgId;
            await using (var conn = await db.OpenConnectionAsync(ct))
            await using (var cmd = new NpgsqlCommand(
                "SELECT org_id, status FROM core.relays WHERE relay_id = @relay_id",
                conn))
            {
                cmd.Parameters.AddWithValue("@relay_id", relayId);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.Json(
                        new { error = "relay-not-found", relayId },
                        statusCode: StatusCodes.Status404NotFound);
                }
                orgId = reader.GetGuid(0);
                var status = reader.GetString(1);
                if (string.Equals(status, "revoked", StringComparison.OrdinalIgnoreCase))
                {
                    return Results.Json(
                        new { error = "relay-revoked", relayId },
                        statusCode: StatusCodes.Status403Forbidden);
                }
            }

            var logger = loggerFactory.CreateLogger("CloudSmith.Api.RelayWebSocket");
            var ws = await ctx.WebSockets.AcceptWebSocketAsync();
            registry.Register(relayId.ToString(), ws);

            // Stamp initial last_seen_at on connect.
            await UpdateLastSeenAsync(db, relayId, ct);

            logger.LogInformation("Relay {RelayId} (org {OrgId}) WebSocket connected", relayId, orgId);

            try
            {
                await HandleRelayWebSocketAsync(ws, relayId, orgId, db, registry, logger, ct);
            }
            finally
            {
                registry.Unregister(relayId.ToString());
                logger.LogInformation("Relay {RelayId} WebSocket disconnected", relayId);
                // Stamp last_seen_at on disconnect so it reflects the true last-contact time.
                try { await UpdateLastSeenAsync(db, relayId, CancellationToken.None); } catch { /* best-effort */ }
            }

            return Results.Empty;
        })
        .AllowAnonymous()
        .WithSummary("Persistent WebSocket hub — enrolled Relay connects here after enrollment (AB#1679).");

        // POST /api/v1/clusters — register a cluster (relay-side or operator-side).
        // Note: the legacy POST /api/v1/clusters on ClusterEndpoints was removed in
        // favour of this bridge-aware endpoint so a single route serves both flows.
        var clusters = app.MapGroup("/api/v1/clusters").WithTags("Clusters");
        clusters.MapPost("/", async (
            RegisterClusterRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
                return orgError!;

            if (string.IsNullOrWhiteSpace(req.Name))
            {
                return Results.Json(
                    new { error = "invalid-request", message = "name is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }
            if (string.IsNullOrWhiteSpace(req.ClusterType) || !AllowedClusterTypes.Contains(req.ClusterType))
            {
                return Results.Json(
                    new { error = "invalid-cluster-type", message = $"clusterType must be one of: {string.Join(", ", AllowedClusterTypes)}." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                INSERT INTO cluster_mgmt.clusters
                    (org_id, site_id, name, cluster_type, relay_id, status)
                VALUES
                    (@org_id, @site_id, @name, @cluster_type, @relay_id, 'unknown')
                RETURNING cluster_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@site_id", (object?)req.SiteId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@name", req.Name);
            cmd.Parameters.AddWithValue("@cluster_type", req.ClusterType);
            cmd.Parameters.AddWithValue("@relay_id", (object?)req.RelayId ?? DBNull.Value);

            try
            {
                var result = await cmd.ExecuteScalarAsync(ct);
                if (result is null)
                {
                    return Results.Json(new { error = "insert-failed" }, statusCode: StatusCodes.Status500InternalServerError);
                }
                var clusterId = (Guid)result;
                return Results.Created($"/api/v1/clusters/{clusterId}", new RegisterClusterResponse(clusterId));
            }
            catch (PostgresException pex) when (pex.SqlState == "23505")
            {
                return Results.Json(
                    new { error = "cluster-name-conflict", name = req.Name },
                    statusCode: StatusCodes.Status409Conflict);
            }
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("platform:write")))
        .WithSummary("Register a cluster (relay-attached or operator-issued).");

        // POST /api/v1/inventory/ingest — Relay pushes an array of VM rows.
        // UPSERT semantics: (cluster_id, vm_guid) is the conflict key — the unique
        // index idx_vms_unique_cluster_vmguid created in
        // inventory/M20260519005_CreateInventorySchema. Rows without vm_guid are
        // always inserted as new (the partial index doesn't apply).
        var inventory = app.MapGroup("/api/v1/inventory").WithTags("Inventory");
        inventory.MapPost("/ingest", async (
            List<InventoryItem> items,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
                return orgError!;

            if (items is null || items.Count == 0)
            {
                return Results.Ok(new InventoryIngestResponse(0, 0));
            }

            const string sql = """
                INSERT INTO inventory.virtual_machines
                    (org_id, cluster_id, name, vm_guid, cpu_count, memory_mb, state, last_seen)
                VALUES
                    (@org_id, @cluster_id, @name, @vm_guid, @cpu_count, @memory_mb, @state, now())
                ON CONFLICT (cluster_id, vm_guid) WHERE vm_guid IS NOT NULL
                DO UPDATE SET
                    name        = EXCLUDED.name,
                    cpu_count   = EXCLUDED.cpu_count,
                    memory_mb   = EXCLUDED.memory_mb,
                    state       = EXCLUDED.state,
                    last_seen   = now()
                RETURNING (xmax = 0) AS inserted
                """;

            var inserted = 0;
            var updated = 0;

            await using var conn = await db.OpenConnectionAsync(ct);
            foreach (var item in items)
            {
                if (string.IsNullOrWhiteSpace(item.Name) || item.ClusterId == Guid.Empty)
                {
                    continue;
                }

                await using var cmd = new NpgsqlCommand(sql, conn);
                cmd.Parameters.AddWithValue("@org_id", orgId);
                cmd.Parameters.AddWithValue("@cluster_id", item.ClusterId);
                cmd.Parameters.AddWithValue("@name", item.Name);
                cmd.Parameters.AddWithValue("@vm_guid", (object?)item.VmGuid ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@cpu_count", (object?)item.CpuCount ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@memory_mb", (object?)item.MemoryMb ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@state", (object?)item.State ?? "unknown");

                var result = await cmd.ExecuteScalarAsync(ct);
                if (result is bool wasInsert && wasInsert)
                {
                    inserted++;
                }
                else
                {
                    updated++;
                }
            }

            return Results.Ok(new InventoryIngestResponse(inserted, updated));
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("inventory:write")))
        .WithSummary("Relay-side bulk inventory ingest (UPSERT by cluster_id + vm_guid).");

        // POST /api/v1/health/probe-result — Relay pushes a per-cluster health probe.
        // Updates cluster_mgmt.clusters.status and stamps last_health_check.
        var health = app.MapGroup("/api/v1/health").WithTags("Health");
        health.MapPost("/probe-result", async (
            HealthProbeRequest req,
            NpgsqlDataSource db,
            HttpContext ctx,
            CancellationToken ct) =>
        {
            if (!TryGetOrgId(ctx, out var orgId, out var orgError))
                return orgError!;

            if (req.ClusterId == Guid.Empty || string.IsNullOrWhiteSpace(req.Status))
            {
                return Results.Json(
                    new { error = "invalid-request", message = "clusterId and status are required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }
            var status = req.Status.ToLowerInvariant();
            if (!AllowedHealthStatuses.Contains(status))
            {
                return Results.Json(
                    new { error = "invalid-status", message = $"status must be one of: {string.Join(", ", AllowedHealthStatuses)}." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            const string sql = """
                UPDATE cluster_mgmt.clusters
                SET status = @status, last_health_check = now()
                WHERE org_id = @org_id AND cluster_id = @cluster_id
                RETURNING cluster_id
                """;

            await using var conn = await db.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@cluster_id", req.ClusterId);
            cmd.Parameters.AddWithValue("@status", status);

            var result = await cmd.ExecuteScalarAsync(ct);
            if (result is null || result is DBNull)
            {
                return Results.NotFound(new { error = "cluster-not-found", clusterId = req.ClusterId });
            }

            // The detailed `checks` payload is accepted for forward-compat but not
            // persisted yet — cluster_mgmt.health_snapshots is the proper home and
            // wiring it up is a follow-up (AB#TBD).
            _ = req.Checks;

            return Results.NoContent();
        })
        .RequireAuthorization(p => p.AddRequirements(new PermissionRequirement("monitoring:write")))
        .WithSummary("Relay-side push of a cluster health probe (updates cluster status + last_health_check).");

        return app;
    }

    private static RelayResponse ReadRelay(NpgsqlDataReader reader)
    {
        return new RelayResponse(
            RelayId: reader.GetGuid(0),
            OrgId: reader.GetGuid(1),
            SiteId: reader.IsDBNull(2) ? (Guid?)null : reader.GetGuid(2),
            DisplayName: reader.GetString(3),
            Status: reader.GetString(4),
            EnrolledAt: reader.GetDateTime(5).ToString("o"),
            LastSeenAt: reader.IsDBNull(6) ? null : reader.GetDateTime(6).ToString("o"));
    }

    private static bool TryGetOrgId(HttpContext ctx, out Guid orgId, out IResult? error)
    {
        orgId = Guid.Empty;
        var orgIdClaim = ctx.User.FindFirstValue("org_id");
        if (string.IsNullOrEmpty(orgIdClaim) || !Guid.TryParse(orgIdClaim, out orgId))
        {
            error = Results.Json(new { error = "missing-org-context" }, statusCode: StatusCodes.Status400BadRequest);
            return false;
        }
        error = null;
        return true;
    }

    private static bool TryGetUserId(HttpContext ctx, out Guid userId, out IResult? error)
    {
        userId = Guid.Empty;
        var userIdClaim = ctx.User.FindFirstValue("sub");
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out userId))
        {
            error = Results.Json(new { error = "missing-user-context" }, statusCode: StatusCodes.Status400BadRequest);
            return false;
        }
        error = null;
        return true;
    }

    private static string ComputeSha256Hex(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        var sb = new StringBuilder(hash.Length * 2);
        for (var i = 0; i < hash.Length; i++)
        {
            sb.Append(hash[i].ToString("x2"));
        }
        return sb.ToString();
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    // -------------------------------------------------------------------------
    // WebSocket hub — frame dispatch (AB#1679)
    // -------------------------------------------------------------------------

    /// <summary>
    /// JSON options for deserializing inbound relay wire frames.
    /// The relay wire format is <c>{"$type":"...", ...}</c>; we read the
    /// discriminator manually with <see cref="JsonDocument"/> to keep the
    /// API side free of any relay-SDK dependency.
    /// </summary>
    private static readonly JsonSerializerOptions WsJsonOpts =
        new(JsonSerializerDefaults.Web);

    private static async Task HandleRelayWebSocketAsync(
        WebSocket ws,
        Guid relayId,
        Guid orgId,
        NpgsqlDataSource db,
        IConnectedRelayRegistry registry,
        ILogger logger,
        CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            using var assembler = new MemoryStream();
            while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
            {
                assembler.SetLength(0);
                WebSocketReceiveResult result;
                do
                {
                    result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        if (ws.State == WebSocketState.CloseReceived)
                        {
                            await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "peer closed", ct);
                        }
                        return;
                    }
                    assembler.Write(buffer, 0, result.Count);
                }
                while (!result.EndOfMessage);

                if (assembler.Length == 0) continue;

                try
                {
                    await DispatchRelayFrameAsync(
                        assembler.ToArray().AsMemory(),
                        relayId, orgId, db, logger, ct);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Relay {RelayId}: error dispatching frame ({Bytes} bytes)",
                        relayId, assembler.Length);
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task DispatchRelayFrameAsync(
        ReadOnlyMemory<byte> frame,
        Guid relayId,
        Guid orgId,
        NpgsqlDataSource db,
        ILogger logger,
        CancellationToken ct)
    {
        string? msgType;
        try
        {
            using var doc = JsonDocument.Parse(frame);
            msgType = doc.RootElement.TryGetProperty("$type", out var t) ? t.GetString() : null;
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "Relay {RelayId}: malformed JSON frame — discarding", relayId);
            return;
        }

        switch (msgType)
        {
            case "heartbeat":
                await UpdateLastSeenAsync(db, relayId, ct);
                logger.LogDebug("Relay {RelayId}: heartbeat", relayId);
                break;

            case "inventory.push":
                await HandleInventoryPushAsync(frame, relayId, orgId, db, logger, ct);
                break;

            case "health.push":
                await HandleHealthPushAsync(frame, relayId, orgId, db, logger, ct);
                break;

            case "job.ack":
                logger.LogInformation("Relay {RelayId}: job.ack received (MVP — no persistent action)", relayId);
                break;

            default:
                logger.LogDebug("Relay {RelayId}: unknown message type '{Type}' — ignoring", relayId, msgType);
                break;
        }
    }

    private static async Task HandleInventoryPushAsync(
        ReadOnlyMemory<byte> frame,
        Guid relayId,
        Guid orgId,
        NpgsqlDataSource db,
        ILogger logger,
        CancellationToken ct)
    {
        // Minimal in-line parse: { "$type":"inventory.push", "clusterId":"...", "vms":[...] }
        using var doc = JsonDocument.Parse(frame);
        var root = doc.RootElement;

        if (!root.TryGetProperty("clusterId", out var cidEl)
            || cidEl.GetString() is not { } clusterIdStr
            || !Guid.TryParse(clusterIdStr, out var clusterId))
        {
            logger.LogWarning("Relay {RelayId}: inventory.push missing or invalid clusterId", relayId);
            return;
        }

        if (!root.TryGetProperty("vms", out var vmsEl)
            || vmsEl.ValueKind != JsonValueKind.Array)
        {
            logger.LogWarning("Relay {RelayId}: inventory.push missing vms array", relayId);
            return;
        }

        const string sql = """
            INSERT INTO inventory.virtual_machines
                (org_id, cluster_id, name, vm_guid, cpu_count, memory_mb, state, last_seen)
            VALUES
                (@org_id, @cluster_id, @name, @vm_guid, @cpu_count, @memory_mb, @state, now())
            ON CONFLICT (cluster_id, vm_guid) WHERE vm_guid IS NOT NULL
            DO UPDATE SET
                name        = EXCLUDED.name,
                cpu_count   = EXCLUDED.cpu_count,
                memory_mb   = EXCLUDED.memory_mb,
                state       = EXCLUDED.state,
                last_seen   = now()
            """;

        var inserted = 0;
        await using var conn = await db.OpenConnectionAsync(ct);
        foreach (var vm in vmsEl.EnumerateArray())
        {
            var name    = vm.TryGetProperty("name", out var n) ? n.GetString() : null;
            var vmGuid  = vm.TryGetProperty("vmId", out var g) ? g.GetString() : null;
            var cpuCount = vm.TryGetProperty("cpuCount", out var c) ? (object?)c.GetInt32() : DBNull.Value;
            // MemoryBytes (relay) → MemoryMb (PG): divide by 1_048_576.
            long? memoryMb = null;
            if (vm.TryGetProperty("memoryBytes", out var mb) && mb.ValueKind == JsonValueKind.Number)
                memoryMb = mb.GetInt64() / 1_048_576;
            var rawState = vm.TryGetProperty("state", out var s) ? s.GetString() ?? "unknown" : "unknown";
            // Normalize Hyper-V EnabledState strings to VmState enum names used by the read path.
            var state = rawState.ToLowerInvariant() switch
            {
                "running"               => "running",
                "off" or "stopped"      => "stopped",
                "paused"                => "paused",
                "saved" or "suspended"  => "saved",
                "starting"              => "starting",
                "stopping"              => "stopping",
                _                       => "unknown",
            };

            if (string.IsNullOrWhiteSpace(name)) continue;

            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@org_id", orgId);
            cmd.Parameters.AddWithValue("@cluster_id", clusterId);
            cmd.Parameters.AddWithValue("@name", name);
            cmd.Parameters.AddWithValue("@vm_guid", (object?)vmGuid ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@cpu_count", cpuCount ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@memory_mb", (object?)memoryMb ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@state", state);
            await cmd.ExecuteNonQueryAsync(ct);
            inserted++;
        }

        logger.LogInformation("Relay {RelayId}: inventory.push cluster={ClusterId} vms={Count}",
            relayId, clusterId, inserted);
    }

    private static async Task HandleHealthPushAsync(
        ReadOnlyMemory<byte> frame,
        Guid relayId,
        Guid orgId,
        NpgsqlDataSource db,
        ILogger logger,
        CancellationToken ct)
    {
        // { "$type":"health.push", "clusterId":"...", "status":"healthy", "checks":[...] }
        using var doc = JsonDocument.Parse(frame);
        var root = doc.RootElement;

        if (!root.TryGetProperty("clusterId", out var cidEl)
            || cidEl.GetString() is not { } clusterIdStr
            || !Guid.TryParse(clusterIdStr, out var clusterId))
        {
            logger.LogWarning("Relay {RelayId}: health.push missing or invalid clusterId", relayId);
            return;
        }

        var status = root.TryGetProperty("status", out var stEl) ? stEl.GetString() ?? "unknown" : "unknown";
        if (!AllowedHealthStatuses.Contains(status)) status = "unknown";

        await using var conn = await db.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("""
            UPDATE cluster_mgmt.clusters
            SET status = @status, last_health_check = now()
            WHERE org_id = @org_id AND cluster_id = @cluster_id
            """, conn);
        cmd.Parameters.AddWithValue("@org_id", orgId);
        cmd.Parameters.AddWithValue("@cluster_id", clusterId);
        cmd.Parameters.AddWithValue("@status", status);
        await cmd.ExecuteNonQueryAsync(ct);

        logger.LogInformation("Relay {RelayId}: health.push cluster={ClusterId} status={Status}",
            relayId, clusterId, status);
    }

    private static async Task UpdateLastSeenAsync(
        NpgsqlDataSource db,
        Guid relayId,
        CancellationToken ct)
    {
        await using var conn = await db.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE core.relays SET last_seen_at = now() WHERE relay_id = @relay_id",
            conn);
        cmd.Parameters.AddWithValue("@relay_id", relayId);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
