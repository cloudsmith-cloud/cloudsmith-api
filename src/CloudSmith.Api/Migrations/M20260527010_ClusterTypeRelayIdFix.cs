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
        Execute.Sql("""
            ALTER TABLE cluster_mgmt.clusters
                ADD COLUMN IF NOT EXISTS cluster_type text
                    CHECK (cluster_type IN ('HyperV','AzureLocal','WSFC'));

            ALTER TABLE cluster_mgmt.clusters
                ADD COLUMN IF NOT EXISTS relay_id uuid
                    REFERENCES core.relays (relay_id) ON DELETE SET NULL;

            CREATE INDEX IF NOT EXISTS idx_clusters_relay_id
                ON cluster_mgmt.clusters (relay_id)
                WHERE relay_id IS NOT NULL;

            ALTER TABLE cluster_mgmt.clusters ALTER COLUMN site_id DROP NOT NULL;
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
