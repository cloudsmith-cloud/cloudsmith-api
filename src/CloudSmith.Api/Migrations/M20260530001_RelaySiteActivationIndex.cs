// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#2442 — Relay-site association and site activation status.
/// Adds a partial index on core.relays (site_id, last_seen_at) to accelerate
/// the activation-status correlated subquery used by GET /api/v1/platform/sites.
/// The index is scoped to non-revoked relays with a site assignment.
/// </summary>
[Migration(20260530001, "core.relays — add idx_relays_site_last_seen for activation-status queries (AB#2442)")]
public sealed class M20260530001_RelaySiteActivationIndex : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_indexes
                    WHERE schemaname = 'core'
                    AND tablename   = 'relays'
                    AND indexname   = 'idx_relays_site_last_seen'
                ) THEN
                    CREATE INDEX idx_relays_site_last_seen
                        ON core.relays (site_id, last_seen_at DESC)
                        WHERE site_id IS NOT NULL AND status != 'revoked';
                END IF;
            END $$;
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
