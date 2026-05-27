// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// Corrective migration — ensures all columns on core.notifications exist.
/// The table may have been partially created by an earlier failed migration run;
/// migration 004 + 008 ensured the table and 'read' column exist. This migration
/// idempotently adds all remaining columns that may be absent from a partial prior deploy.
/// Forward-only per CloudSmith migration policy.
/// </summary>
[Migration(20260527009, "Notifications — add all missing columns idempotently (corrective)")]
public sealed class M20260527009_NotificationsFullSchemaFix : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            -- Add each column idempotently in case the table exists from a prior partial deploy.
            ALTER TABLE core.notifications ADD COLUMN IF NOT EXISTS user_id         uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
            ALTER TABLE core.notifications ADD COLUMN IF NOT EXISTS org_id          uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
            ALTER TABLE core.notifications ADD COLUMN IF NOT EXISTS type            text        NOT NULL DEFAULT 'unknown';
            ALTER TABLE core.notifications ADD COLUMN IF NOT EXISTS title           text        NOT NULL DEFAULT '';
            ALTER TABLE core.notifications ADD COLUMN IF NOT EXISTS message         text        NOT NULL DEFAULT '';
            ALTER TABLE core.notifications ADD COLUMN IF NOT EXISTS metadata        jsonb       NULL;
            ALTER TABLE core.notifications ADD COLUMN IF NOT EXISTS created_at      timestamptz NOT NULL DEFAULT now();

            -- Re-create indexes idempotently.
            CREATE INDEX IF NOT EXISTS ix_notifications_user_created
                ON core.notifications (user_id, created_at DESC);
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
