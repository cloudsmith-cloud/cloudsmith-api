// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#4843 — batch items ARE jobs (Wave 1 decision, design/api-surface/job-batch-endpoints.md):
/// every core.job_batch_items row links 1:1 to a core.jobs row and the batch layer
/// becomes aggregation-only. Adds:
/// <list type="bullet">
/// <item>job_batch_items.job_id — FK to core.jobs, unique (1:1 item↔job). Nullable
/// for pre-Wave-1 legacy rows; every new item sets it.</item>
/// <item>job_batches.idempotency_key — batch-level create dedupe per contract §4.1
/// (duplicate key returns the existing batch).</item>
/// </list>
/// </summary>
[Migration(20260703103, "core.job_batch_items.job_id link + core.job_batches.idempotency_key (AB#4843)")]
public sealed class M20260703103_JobBatchItemsLinkJobs : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            ALTER TABLE core.job_batch_items
                ADD COLUMN IF NOT EXISTS job_id uuid REFERENCES core.jobs (job_id) ON DELETE SET NULL;

            CREATE UNIQUE INDEX IF NOT EXISTS ux_job_batch_items_job_id
                ON core.job_batch_items (job_id)
                WHERE job_id IS NOT NULL;

            ALTER TABLE core.job_batches
                ADD COLUMN IF NOT EXISTS idempotency_key text;

            CREATE UNIQUE INDEX IF NOT EXISTS ux_job_batches_org_idempotency_key
                ON core.job_batches (org_id, idempotency_key)
                WHERE idempotency_key IS NOT NULL;
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
