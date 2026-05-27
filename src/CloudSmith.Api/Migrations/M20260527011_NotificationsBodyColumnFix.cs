// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// Corrective migration — makes the stale 'body' column on core.notifications nullable.
/// An older schema version created this column as NOT NULL, but current code never
/// populates it (message/title carry the content). Making it nullable prevents the
/// 23502 constraint violation in JobBatchProcessor.EmitBatchNotificationAsync.
/// Forward-only per CloudSmith migration policy.
/// </summary>
[Migration(20260527011, "core.notifications — drop NOT NULL on body column if it exists (corrective)")]
public sealed class M20260527011_NotificationsBodyColumnFix : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'core'
                    AND table_name    = 'notifications'
                    AND column_name   = 'body'
                    AND is_nullable   = 'NO'
                ) THEN
                    ALTER TABLE core.notifications ALTER COLUMN body DROP NOT NULL;
                END IF;
            END $$;
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
