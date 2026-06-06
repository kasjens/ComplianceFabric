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

## Sign your commits

This project uses the Developer Certificate of Origin (DCO). Sign off every commit:

```bash
git commit -s -m "Add Annex 11 audit-trail control mapping"
```

The sign-off line states that you wrote the change or have the right to submit it under the project license.

## Review and merge

A maintainer reviews each pull request. Changes to control mappings get extra scrutiny, since a wrong mapping produces wrong evidence. A pull request merges once it has a maintainer approval and passes checks. The merge record is part of the project's own change history.

## License of contributions

By contributing, you agree that your contributions are licensed under the Apache License 2.0, the same license as the project.
