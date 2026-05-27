// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#1930 — User preferences table for per-user dashboard layout persistence.
/// Stores arbitrary JSON keyed by (user_id, key) — dashboard_layout is the first consumer.
/// </summary>
[Migration(20260527003, "User preferences — dashboard layout persistence (AB#1930)")]
public sealed class M20260527003_CreateUserPreferences : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            CREATE TABLE IF NOT EXISTS core.user_preferences (
                user_id     uuid        NOT NULL,
                key         text        NOT NULL,
                value       jsonb       NOT NULL DEFAULT '{}'::jsonb,
                updated_at  timestamptz NOT NULL DEFAULT now(),
                PRIMARY KEY (user_id, key)
            );
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
