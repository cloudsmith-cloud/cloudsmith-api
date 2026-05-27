// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// Corrective migration — ensures cluster_mgmt.clusters has the cluster_type and relay_id
/// columns added by M20260523001_AddClusterTypeAndRelayId in cloudsmith-cluster-mgmt.
/// That migration may have been recorded in VersionInfo from a prior deployment but
/// the columns may be absent if the table was re-created by a later fresh schema run.
/// Forward-only per CloudSmith migration policy.
/// </summary>
[Migration(20260527010, "cluster_mgmt — add cluster_type + relay_id columns idempotently (corrective)")]
public sealed class M20260527010_ClusterTypeRelayIdFix : Migration
{
    public override void Up()
    {
        // Guard: this corrective migration is a no-op on fresh deployments where
        // cluster_mgmt.clusters does not yet exist (it will be created by the
        // CloudSmith.ClusterMgmt package migrations that run after the API migrations).
        // On environments with a pre-existing partial schema, this adds the missing columns.
        Execute.Sql("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'cluster_mgmt'
                    AND table_name = 'clusters'
                ) THEN
                    -- Add cluster_type column if missing
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'cluster_mgmt'
                        AND table_name = 'clusters'
                        AND column_name = 'cluster_type'
                    ) THEN
                        ALTER TABLE cluster_mgmt.clusters
                            ADD COLUMN cluster_type text
                                CHECK (cluster_type IN ('HyperV','AzureLocal','WSFC'));
                    END IF;

                    -- Add relay_id column if missing
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'cluster_mgmt'
                        AND table_name = 'clusters'
                        AND column_name = 'relay_id'
                    ) THEN
                        ALTER TABLE cluster_mgmt.clusters
                            ADD COLUMN relay_id uuid
                                REFERENCES core.relays (relay_id) ON DELETE SET NULL;
                        CREATE INDEX IF NOT EXISTS idx_clusters_relay_id
                            ON cluster_mgmt.clusters (relay_id)
                            WHERE relay_id IS NOT NULL;
                    END IF;

                    -- Drop NOT NULL on site_id if it is currently NOT NULL
                    -- (safe to run even if already nullable)
                    ALTER TABLE cluster_mgmt.clusters ALTER COLUMN site_id DROP NOT NULL;
                END IF;
            END $$;
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
