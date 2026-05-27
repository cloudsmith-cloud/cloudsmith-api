// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using FluentMigrator;

namespace CloudSmith.Api.Migrations;

/// <summary>
/// AB#1933 — Platform-level identity provider registration table.
/// Distinct from core.identity_providers (org-scoped IdP config used by the existing
/// IdentityProviderEndpoints). This table records the platform-wide provider registered
/// during setup/post-setup — Entra ID with Graph-provisioned app registration or
/// manual OIDC/Entra config. Secret is stored encrypted via the master key reference.
/// </summary>
[Migration(20260527006, "Platform identity providers — Entra Graph auto-create (AB#1933)")]
public sealed class M20260527006_CreatePlatformIdentityProviders : Migration
{
    public override void Up()
    {
        Execute.Sql("""
            CREATE TABLE IF NOT EXISTS core.platform_identity_providers (
                provider_id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
                provider_type       text        NOT NULL,
                tenant_id           text        NULL,
                client_id           text        NULL,
                client_secret_enc   text        NULL,
                auto_created        boolean     NOT NULL DEFAULT false,
                status              text        NOT NULL DEFAULT 'configured',
                created_at          timestamptz NOT NULL DEFAULT now(),
                updated_at          timestamptz NOT NULL DEFAULT now()
            );
            """);
    }

    public override void Down()
    {
        // Forward-only migrations — Down() is intentionally a no-op per CloudSmith migration policy
    }
}
