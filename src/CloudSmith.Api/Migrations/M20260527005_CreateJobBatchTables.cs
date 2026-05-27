// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#1931 — Bulk job batch tables.
/// job_batches tracks the parent batch record;
/// job_batch_items tracks each individual resource-id sub-task.
/// </summary>
[Migration(20260527005, "Job batch tables — bulk operation batching (AB#1931)")]
public sealed class M20260527005_CreateJobBatchTables : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            CREATE TABLE IF NOT EXISTS core.job_batches (
                batch_id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id          uuid        NOT NULL,
                created_by      uuid        NOT NULL,
                operation       text        NOT NULL,
                parameters      jsonb       NULL,
                status          text        NOT NULL DEFAULT 'queued',
                total_items     int         NOT NULL DEFAULT 0,
                completed_items int         NOT NULL DEFAULT 0,
                failed_items    int         NOT NULL DEFAULT 0,
                created_at      timestamptz NOT NULL DEFAULT now(),
                updated_at      timestamptz NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS core.job_batch_items (
                item_id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
                batch_id        uuid        NOT NULL REFERENCES core.job_batches(batch_id) ON DELETE CASCADE,
                resource_id     text        NOT NULL,
                status          text        NOT NULL DEFAULT 'queued',
                error_message   text        NULL,
                started_at      timestamptz NULL,
                completed_at    timestamptz NULL
            );

            CREATE INDEX IF NOT EXISTS ix_job_batch_items_batch
                ON core.job_batch_items (batch_id, status);
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
