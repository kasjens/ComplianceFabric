# Contributing

Thanks for your interest in the Compliance Fabric. This project is built in the open, and contributions of control mappings, policy templates, integrations, documentation, and issues are all welcome.

## Before you start

- Read [`docs/00-overview.md`](docs/00-overview.md) and [`docs/01-architecture.md`](docs/01-architecture.md) so your change fits the design.
- Read [`GOVERNANCE.md`](GOVERNANCE.md) for how decisions are made and where the open-core boundary sits.
- Follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) in all project spaces.

## Ways to contribute

- Control mappings: OSCAL profiles and component definitions for frameworks the project does not cover yet.
- Policy templates: Kyverno or OPA policies that implement a mapped control.
- Integrations: connectors to policy engines, registries, or evidence stores.
- Documentation: corrections, examples, and clearer explanations.
- Issues: bug reports and well-scoped feature requests.

If you plan a large change, open an issue first so the direction can be agreed before you spend time on it.

## Development workflow

1. Fork the repository and create a branch from `main`.
2. Use a descriptive branch name, for example `mapping/annex11-audit-trail` or `docs/fix-architecture-flow`.
3. Make focused commits. One logical change per commit.
4. Open a pull request against `main` and fill in the template.

## What CI runs on your pull request

Locally, `go test -race ./...` is the whole unit suite and needs nothing but Go — the build is stdlib-only. The suite runs on Linux, macOS and Windows; if you add a test, keep it portable (embed paths in JSON fixtures through the `jsonPath` helper rather than raw, and do not shell out to tools that only exist on one platform).

Beyond the unit suite, CI runs end-to-end jobs that drive the real `fabric` binary: live admission against a kind cluster, the inline gateway and the live gateway proxy, the SBOM and release-gate paths with syft, and a job that exercises every CLI subcommand.

**One job cannot run on a pull request from a fork: `keyless-e2e`.** It proves Sigstore keyless signature verification by signing a test image with the repository's own GitHub Actions OIDC identity, and a fork cannot mint that identity — so the job is skipped rather than failed there. This means **a fork PR does not get the keyless proof**, and a maintainer runs it on the branch before merging anything that touches image-signature policy or the admission path. If your change is in that area, say so in the PR description so it gets that check.

## Sign your commits

This project uses the Developer Certificate of Origin (DCO). Sign off every commit:

```bash
git commit -s -m "Add Annex 11 audit-trail control mapping"
```

The sign-off line states that you wrote the change or have the right to submit it under the project license.

## Branch and tag protection

`main` is protected. A change reaches it through a pull request that:

- has an approving review from a code owner (see [`.github/CODEOWNERS`](.github/CODEOWNERS)), with stale approvals dismissed when new commits land;
- has every required CI check green, with the branch up to date with `main`;
- has all review conversations resolved.

History on `main` is linear — merge commits are disabled, so use squash or rebase — and the branch cannot be force-pushed or deleted.

**`keyless-e2e` is deliberately not a required check.** It cannot run on a pull request from a fork (see above), and a required check that never runs would block such a PR forever. A maintainer runs it on the branch instead before merging anything that touches image-signature policy or the admission path.

Release tags (`v*`) cannot be deleted or moved once pushed. A release's evidence — its SBOM, provenance and signed evidence ledger — is bound to the tag it was built from, so moving a tag would silently invalidate every artifact that references it.

## Review and merge

A maintainer reviews each pull request. Changes to control mappings get extra scrutiny, since a wrong mapping produces wrong evidence. A pull request merges once it has a maintainer approval and passes checks. The merge record is part of the project's own change history.

## License of contributions

By contributing, you agree that your contributions are licensed under the Apache License 2.0, the same license as the project.
