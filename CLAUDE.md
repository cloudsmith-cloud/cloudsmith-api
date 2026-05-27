# CLAUDE.md — cloudsmith-api

Claude Code context for `cloudsmith-api` — one of the code repos in the CloudSmith open-source project.

## What this repo is

.NET 9 Minimal API host — module loader, SignalR hubs, OpenAPI spec, and RBAC enforcement

For project-wide architecture, ADRs, and the master plan, see [`cloudsmith-internal`](../cloudsmith-internal/) (private). This repo focuses on code.

## Stack

| Layer | Stack |
|---|---|
| Backend  | .NET 9 + C# |
| Build    | Docker (multi-stage) |

## Standards

This repo follows all HCS platform standards. The cross-cutting rules:

- Markdown only — no Word docs.
- Commit format: `type(scope): short description` (feat/fix/docs/chore/refactor).
- ADO reference: `AB#<id>` in commit messages when applicable.
- **No secrets, tokens, or IDs committed — ever.** The `block-secrets.ps1` hook enforces this.
- Work direct-to-main (Kris's standing order; GitHub App bypasses branch protection).

## Key facts

| Fact | Value |
|---|---|
| GitHub org | cloudsmith-cloud |
| ADO project | CloudSmith |
| Auth | GitHub App (`hcs-platform-app`) |

> Azure subscription, Key Vault name, ADO org URL, install IDs, and other infrastructure values live in the **private** `cloudsmith-internal/CLAUDE.md` and in the platform repo — not in this public repo.

## Build & test infrastructure — use the tenant, don't ask

Per `cloudsmith-internal/CLAUDE.md` (private):

- **No local builds.** If a build needs `pnpm install` or `dotnet build` and the classifier blocks local execution, use the build VM pattern (`workstream-build-vm` skill).
- **No PR branches.** Push direct-to-main via `/ghapp-push` (the GitHub App bypasses branch protection).
- **Cleanup is a standing order.** Test resource groups created during builds/tests get deleted on completion via `/cleanup-rgs`.

## Repo-specific build / test commands

- `dotnet restore` — restore packages
- `dotnet build` — build solution
- `dotnet test` — run tests

## Hard rules

- Never commit secrets, tokens, passwords, subscription IDs, resource group names, or connection strings.
- Never run `git push --force` on main; `block-destructive.ps1` enforces.
- Never deploy into the protected PaaS dev RG (see private `cloudsmith-internal` for the name); `block-destructive.ps1` enforces.
- Never run the setup wizard for Kris on a fresh PaaS deploy — he walks it himself.
- Reviewer/author model families must differ for any code review.

## Claude Code config

This repo's `.claude/` is bootstrapped from `cloudsmith-internal/.claude/templates/`. The hooks, commands, and skills point at the canonical files in `cloudsmith-internal` via absolute path — no duplication.

If a command, skill, or agent is missing here, it lives in `cloudsmith-internal/.claude/`. Run `/repo-init` to re-bootstrap.

