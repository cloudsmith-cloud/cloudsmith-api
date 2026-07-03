// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#2766 (API half) — adds the env column (text NOT NULL DEFAULT 'default', per the
/// frozen contract §3) to the host and cluster records: cluster_mgmt.clusters and
/// cluster_mgmt.nodes. Batch job creation resolves a target's (site_id, env) routing
/// scope from its cluster record (design/api-surface/job-batch-endpoints.md).
///
/// The cluster_mgmt schema is owned by the CloudSmith.ClusterMgmt package
/// (cloudsmith-cluster-mgmt repo); this API-local migration is a guarded additive
/// following the established corrective precedent of M20260527010_ClusterTypeRelayIdFix.
/// It is a no-op on fresh deployments where cluster_mgmt tables do not exist yet
/// (they are created by the package migrations that run after the API migrations);
/// the canonical column addition belongs in a cloudsmith-cluster-mgmt migration.
/// Read paths in this repo tolerate the column's absence until then.
/// </summary>
[Migration(20260703102, "cluster_mgmt.clusters + cluster_mgmt.nodes — add env column idempotently (AB#2766)")]
public sealed class M20260703102_AddEnvToClusterRecords : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'cluster_mgmt'
                    AND table_name = 'clusters'
                ) THEN
                    ALTER TABLE cluster_mgmt.clusters
                        ADD COLUMN IF NOT EXISTS env text NOT NULL DEFAULT 'default';
                END IF;

                IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'cluster_mgmt'
                    AND table_name = 'nodes'
                ) THEN
                    ALTER TABLE cluster_mgmt.nodes
                        ADD COLUMN IF NOT EXISTS env text NOT NULL DEFAULT 'default';
                END IF;
            END $$;
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
