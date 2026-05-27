// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#1591 — Startup bootstrap config table.
/// Stores the master encryption key and the one-time initial admin token hash,
/// both generated on first startup by <see cref="Services.MasterSecretsKeyBootstrap"/>.
/// Uses <c>core</c> schema (already created by M20260519001_CreateCoreSchema in cloudsmith-core).
/// </summary>
[Migration(20260527001, "Bootstrap config — master secrets key and initial admin token (AB#1591)")]
public sealed class M20260527001_CreateBootstrapConfig : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            CREATE TABLE IF NOT EXISTS core.bootstrap_config (
                key         text        PRIMARY KEY,
                value       text        NOT NULL,
                created_at  timestamptz NOT NULL DEFAULT now()
            );
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
