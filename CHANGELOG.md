# Changelog

All notable changes to **cloudsmith-api** will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
The API has not yet adopted SemVer tags; releases below are identified by the
container-image tags pushed to `ghcr.io/cloudsmith-cloud/cloudsmith-api`.

## [Unreleased]

## [2026-05-23-wave3]

### Added

- `RelayEndpoints` — 7 endpoints covering the full Relay lifecycle: issue enrollment token, enroll, list, detail, revoke, `POST /clusters` (cluster registration from a relay), inventory ingest, and health probe-result ingest.
- Module detail endpoints under `PlatformEndpoints`: `Permissions`, `Dependencies`, and `Health`.

### Changed

- Bumped package references: `CloudSmith.Core` 0.4.0 → 0.5.0; `CloudSmith.ClusterMgmt` 0.1.0 → 0.2.0.

## [2026-05-23-wave2]

### Added

- `UsersEndpoints` — list users and issue invitations.
- `AuditEndpoints` — query the audit log.
- `SitesEndpoints` — full CRUD over sites.
- `SecretsEndpoints` — CRUD over secret references.
- `Config` value-list endpoint to back the Config Registry value editor in the portal.

## [2026-05-23-wave1]

### Added

- `PlatformEndpoints` — Modules list, install, and uninstall.
- `IdentityProviderEndpoints` — IdP CRUD plus a `test` action used by the in-platform wizards.

## [2026-05-22]

### Added

- `SetupEndpoints` and `SetupGateMiddleware` implementing the ADR-047 first-run setup wizard.

## [2026-05-21]

### Added

- `AuthEndpoints` — OIDC login flow and local-admin (break-glass) login per ADR-047.
