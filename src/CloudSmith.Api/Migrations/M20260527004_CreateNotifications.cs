// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#1932 — Notifications table for per-user notification feed.
/// Stores job completion/failure alerts and other platform events.
/// </summary>
[Migration(20260527004, "Notifications — per-user notification feed (AB#1932)")]
public sealed class M20260527004_CreateNotifications : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            CREATE TABLE IF NOT EXISTS core.notifications (
                notification_id uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id         uuid        NOT NULL,
                org_id          uuid        NOT NULL,
                type            text        NOT NULL,
                title           text        NOT NULL,
                message         text        NOT NULL,
                read            boolean     NOT NULL DEFAULT false,
                metadata        jsonb       NULL,
                created_at      timestamptz NOT NULL DEFAULT now()
            );

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
