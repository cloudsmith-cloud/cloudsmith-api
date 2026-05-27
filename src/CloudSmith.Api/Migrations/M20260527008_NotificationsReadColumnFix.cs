// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// Corrective migration — ensures the core.notifications table has the 'read' column
/// and its associated partial index even when migration 20260527004 ran against a DB
/// that already had the table from a prior partial/failed deployment.
/// Forward-only per CloudSmith migration policy.
/// </summary>
[Migration(20260527008, "Notifications — add read column + index if missing (corrective)")]
public sealed class M20260527008_NotificationsReadColumnFix : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            -- Add the 'read' column idempotently in case it was absent from a prior partial migration.
            ALTER TABLE core.notifications ADD COLUMN IF NOT EXISTS read boolean NOT NULL DEFAULT false;

            -- Re-create index idempotently (CREATE INDEX IF NOT EXISTS is safe to re-run).
            CREATE INDEX IF NOT EXISTS ix_notifications_org_unread
                ON core.notifications (org_id, read)
                WHERE read = false;
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
