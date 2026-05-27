// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// Corrective migration — drops the stale 'notifications_type_check' constraint on
/// core.notifications. An older schema version restricted the type column to a fixed
/// enum that did not include 'job.batch.completed' / 'job.batch.failed', causing
/// JobBatchProcessor.EmitBatchNotificationAsync to fail with SqlState 23514 on every
/// batch completion. Current code does not enforce a type taxonomy in the DB layer;
/// the type column is treated as an opaque string. Forward-only per migration policy.
/// </summary>
[Migration(20260527012, "core.notifications — drop stale notifications_type_check constraint (corrective)")]
public sealed class M20260527012_NotificationsTypeCheckFix : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.table_constraints
                    WHERE table_schema    = 'core'
                    AND table_name      = 'notifications'
                    AND constraint_name = 'notifications_type_check'
                    AND constraint_type = 'CHECK'
                ) THEN
                    ALTER TABLE core.notifications DROP CONSTRAINT notifications_type_check;
                END IF;
            END $$;
            """);
    }

    public override void Down()
    {
        // Forward-only per CloudSmith migration policy.
    }
}
