# Contributing to cloudsmith-api

Thank you for your interest in contributing to CloudSmith. This project is licensed under [Apache 2.0](LICENSE) and uses the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) instead of a CLA.

## Developer Certificate of Origin

By contributing, you certify that you wrote the contribution or have the right to submit it under the Apache 2.0 license. Sign every commit:

```
git commit -s -m "feat: my change"
```

This adds `Signed-off-by: Your Name <email>` to your commit. The DCO check in CI will fail without it.

## Code of Conduct

This project follows the [CloudSmith Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant v2.1). Violations: conduct@cloudsmith.cloud.

## Getting started

1. Fork the repo and create a feature branch from `main`.
2. Write tests. All PRs require passing CI before merge.
3. Sign your commits (DCO — see above).
4. Open a pull request targeting `main`.

## Commit message format

Uses [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): short description

Longer body (optional). Reference ADO items with AB#NNN.
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`

## Reporting security vulnerabilities

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).