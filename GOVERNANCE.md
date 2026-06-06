# Governance

This document describes how the GxP Compliance Fabric is run, how decisions are made, and where the open-core boundary sits.

## Roles

- Users run the project and report issues.
- Contributors submit pull requests. Anyone can be a contributor.
- Maintainers review and merge changes and guide direction. Maintainers are listed in [`MAINTAINERS.md`](MAINTAINERS.md).
- The lead maintainer resolves ties and sets initial direction. The project starts with a single lead maintainer and moves to a maintainer group as the contributor base grows.

## Decision-making

Most decisions happen by lazy consensus: a proposal in an issue or pull request is accepted if no maintainer objects within a reasonable review window. Larger decisions, such as a new framework, an architecture change, or a governance change, are recorded as an architecture decision record in [`docs/adr/`](docs/adr/) and need agreement from a majority of maintainers.

## Becoming a maintainer

Contributors who submit sound changes over time, review others' work, and engage with the community can be proposed as maintainers by an existing maintainer. The maintainer group decides by majority.

## Open-core boundary

The open-source core in this repository is licensed under Apache 2.0 and is governed by this document. It covers the framework, policy templates, OSCAL control mappings, integrations, and documentation.

A commercial layer is offered separately by the project's commercial sponsor. It includes a hosted control plane, polished audit-pack and validation-report generation, certified GxP control packs, and enterprise support. The commercial layer is not governed by this document and is not part of this repository.

This separation is stated openly so contributors know what they are building and where it sits. Contributions to the open core stay open. The sponsor does not relicense community contributions into closed components. The reasoning is recorded in [`docs/adr/0004-open-core-and-apache-2-0.md`](docs/adr/0004-open-core-and-apache-2-0.md).

## Changing this document

Changes to governance follow the architecture decision record process and need agreement from a majority of maintainers.
