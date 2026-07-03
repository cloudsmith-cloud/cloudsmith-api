// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#2762 (API half) — adds the env column to core.relays per the frozen job
/// dispatch contract (cloudsmith-internal design/api-surface/job-dispatch-contract.md §5):
/// a job is routable to a Relay iff job.site_id = relay.site_id AND job.env = relay.env,
/// strictly — no cross-site or cross-env fallback. env is text NOT NULL DEFAULT 'default'
/// everywhere (contract §3). The Relay presents its env at enrollment.
///
/// core.relays is created by the core-owned migration M20260523008; API-local
/// corrective/additive migrations on core.relays follow the established precedent
/// of M20260530001_RelaySiteActivationIndex.
///
/// Version number is unique across all runners sharing the VersionInfo table
/// (core used 20260703001 in the same wave).
/// </summary>
[Migration(20260703101, "core.relays — add env column + (site_id, env) routing index (AB#2762)")]
public sealed class M20260703101_AddRelayEnv : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            ALTER TABLE core.relays
                ADD COLUMN IF NOT EXISTS env text NOT NULL DEFAULT 'default';

            -- Contract §5: dispatch selection is strict (site_id, env) equality among
            -- connected, non-revoked relays; most recent last_seen_at wins the tie-break.
            CREATE INDEX IF NOT EXISTS idx_relays_site_env_last_seen
                ON core.relays (site_id, env, last_seen_at DESC)
                WHERE site_id IS NOT NULL AND status != 'revoked';
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
