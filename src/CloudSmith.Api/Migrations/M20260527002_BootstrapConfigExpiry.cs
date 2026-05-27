// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// C2 security fix — adds <c>expires_at</c> to <c>core.bootstrap_config</c> so the
/// initial admin token can carry a 30-minute TTL enforced by <c>POST /api/v1/setup</c>.
/// </summary>
[Migration(20260527002, "Bootstrap config — add expires_at for token TTL (C2 security fix)")]
public sealed class M20260527002_BootstrapConfigExpiry : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            ALTER TABLE core.bootstrap_config
                ADD COLUMN IF NOT EXISTS expires_at timestamptz NULL;
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
