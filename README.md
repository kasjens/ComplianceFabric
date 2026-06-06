# GxP Compliance Fabric

A continuous-compliance control and evidence layer for regulated Kubernetes platforms. Author controls once, enforce them as policy, and produce audit-ready evidence on demand.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The Fabric targets life sciences first (GxP) and extends to other regulated sectors such as finance (DORA, NIS2). It builds on open standards and open-source projects already common in regulated platforms: OSCAL, Kyverno, OPA, Sigstore, and GitOps.

## Status

Early open-source project, currently at the documentation and design phase. See `ROADMAP.md` for what comes next, and `CONTRIBUTING.md` if you want to help build it.

## Open-core

The core is open source under Apache 2.0: the framework, policy templates, OSCAL control mappings, integrations, and documentation. A commercial layer is offered separately by Verholm and is not part of this repository: a hosted control plane, polished audit-pack and validation-report generation, certified GxP control packs, and enterprise support. The boundary is described in `GOVERNANCE.md` and the reasoning in `docs/adr/0004-open-core-and-apache-2-0.md`.

The control logic is open on purpose. A quality team and an auditor can read exactly how a control is enforced and evidenced, which is worth more than a black box that asks to be trusted.

## The continuous-compliance loop

1. Author controls as code in OSCAL.
2. Compile controls into Kubernetes policy.
3. Enforce at CI, admission, and runtime.
4. Run regulated workloads and AI agents on a qualified platform.
5. Collect platform state and telemetry as evidence.
6. Map evidence back to controls and report. Gaps feed back to step 1.

## Documentation

Start at the [documentation index](docs/README.md), or open a layer directly.

| Path | Contents |
|---|---|
| `docs/00-overview.md` | Problem, concept, scope, glossary |
| `docs/01-architecture.md` | The six layers, data flow, trust boundaries, deployment model |
| `docs/02-control-authoring.md` | Controls as code in OSCAL |
| `docs/03-policy-enforcement.md` | Compliance-to-Policy, Kyverno, OPA, admission and runtime |
| `docs/04-trusted-delivery.md` | SBOM, SLSA, Sigstore, GitOps change control |
| `docs/05-agent-governance.md` | AI gateway, agent registry, guardrails, tracing |
| `docs/06-platform-substrate.md` | Clusters, workloads, identity, observability |
| `docs/07-evidence-and-audit.md` | Continuous assessment, evidence ledger, audit packs |
| `docs/08-regulatory-mapping.md` | Control-to-technology mapping |
| `docs/09-validation-approach.md` | GAMP 5, CSA, platform versus workload validation |
| `docs/10-build-vs-buy.md` | Open source versus proprietary IP |
| `docs/adr/` | Architecture decision records |
| `reference/architecture.drawio` | The reference architecture diagram |

## Project files

| File | Purpose |
|---|---|
| `LICENSE` | Apache License 2.0 |
| `NOTICE` | Copyright and sponsorship notice |
| `CONTRIBUTING.md` | How to contribute, including commit sign-off |
| `CODE_OF_CONDUCT.md` | Contributor Covenant 2.1 |
| `GOVERNANCE.md` | Roles, decisions, and the open-core boundary |
| `MAINTAINERS.md` | Who reviews and merges |
| `SECURITY.md` | How to report vulnerabilities |
| `ROADMAP.md` | Planned phases |
| `CHANGELOG.md` | Notable changes |

## Contributing

Contributions are welcome: control mappings, policy templates, integrations, documentation, and issues. Start with `CONTRIBUTING.md` and `ROADMAP.md`, and see `GOVERNANCE.md` for how decisions are made and how to become a maintainer. All participants follow `CODE_OF_CONDUCT.md`.

## Security

Report vulnerabilities privately as described in `SECURITY.md`. Do not open public issues for security problems.

## What it is not

The Fabric generates and maintains evidence. It does not replace the quality sign-off or the validation decision. That separation matches the risk-based assurance approach in GAMP 5 Second Edition and the FDA Computer Software Assurance (CSA) guidance. See `docs/09-validation-approach.md`.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
