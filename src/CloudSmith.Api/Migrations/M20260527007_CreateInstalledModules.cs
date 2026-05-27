// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#1925 — Published Module Catalog: local install/enable state table.
/// Records which catalog modules have been installed on this platform instance.
/// The catalog itself is proxied from the upstream GHCR registry via ICloudSmithModuleCatalog.
/// This table merges install/enable state into the catalog response.
/// </summary>
[Migration(20260527007, "Installed modules catalog state (AB#1925)")]
public sealed class M20260527007_CreateInstalledModules : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            CREATE TABLE IF NOT EXISTS core.installed_modules (
                id              TEXT        PRIMARY KEY,
                version         TEXT        NOT NULL,
                is_enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
                installed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                installed_by    TEXT        NOT NULL DEFAULT 'system'
            );
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
