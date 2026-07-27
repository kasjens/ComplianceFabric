# Compliance Fabric

A continuous-compliance control and evidence layer for regulated Kubernetes platforms. Author controls once, enforce them as policy, and produce audit-ready evidence on demand.

![Compliance Fabric concept overview: author once in OSCAL, enforce with Kyverno, record to a continuous evidence ledger, and crosswalk one control set to DORA, NIS2, and ISO/IEC 42001](compliance-fabric-concept-overview.png)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The Fabric targets life sciences first (GxP) and extends to other regulated sectors such as finance (DORA, NIS2). It builds on open standards and open-source projects already common in regulated platforms: OSCAL, Kyverno, OPA, Sigstore, and GitOps.

## Status

Active development. The core is a standard-library-only Go CLI (`fabric`), built test-first, that already runs the continuous-compliance loop end to end:

- **Control authoring, policy, and enforcement (Phase 1, done).** OSCAL catalogs (EU GMP Annex 11, 21 CFR Part 11), a pharma MES baseline profile, and a native composer (`fabric generate`) that compiles the selected controls into a Kyverno policy library with `fabric.control-id` traceability. Admission and runtime enforcement are proven on a live kind cluster in CI.
- **Trusted delivery (Phase 2, done).** SBOM and SLSA provenance evidence producers, Sigstore keyless signature verification at admission, GitOps change-control evidence, and a release evidence gate (`fabric release-gate`) that binds SBOM/provenance generation into the release pipeline. Proven end to end with syft and cosign in CI.
- **Evidence and reporting (Phase 3, done).** A hash-chained, append-only evidence ledger; seven evidence producers feeding it; OSCAL assessment-results and a control-posture rollup with a live dashboard; and a continuous collector that polls sources and records only state changes.
- **AI agent governance (Phase 4, in progress).** A versioned agent/prompt/tool registry, an inline gateway that admits or blocks agent interactions at request time (content guardrails, a model allow-list, input/output screening, and per-agent rate and cost limits), a live LLM/MCP traffic proxy (`fabric gateway-proxy`) that enforces the same gates on the real model/tool call before it reaches the upstream and screens the model's response on the way back — incrementally, event by event, for streamed (SSE) responses — pre-promotion evaluation gates, and interaction tracing that ingests the gateway log and OpenTelemetry OTLP/JSON. What remains is operational hardening (a reference deployment) rather than new control logic.
- **Cross-sector crosswalks (Phase 5, done).** A crosswalk engine (`fabric crosswalk`) that reuses controls the Fabric already enforces to answer a second framework's citations with no new enforcement, with worked DORA, NIS2, and ISO/IEC 42001 crosswalks built from the existing GxP and agent-layer controls. Crosswalks are first-class control-tree artifacts whose referential integrity `fabric validate` checks.

Phase 4's data-and-logic scope is now complete; what remains is operational hardening (a reference deployment) rather than new control logic. See [`ROADMAP.md`](ROADMAP.md) for detail, [`CHANGELOG.md`](CHANGELOG.md) for recent changes, and [`CONTRIBUTING.md`](CONTRIBUTING.md) if you want to help build it.

## Open-core

The core is open source under Apache 2.0: the framework, policy templates, OSCAL control mappings, integrations, and documentation. A commercial layer is offered separately by the project's commercial sponsor and is not part of this repository: a hosted control plane, polished audit-pack and validation-report generation, certified GxP control packs, and enterprise support. The boundary is described in [`GOVERNANCE.md`](GOVERNANCE.md) and the reasoning in [`docs/adr/0004-open-core-and-apache-2-0.md`](docs/adr/0004-open-core-and-apache-2-0.md).

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
| [`docs/00-overview.md`](docs/00-overview.md) | Problem, concept, scope, glossary |
| [`docs/01-architecture.md`](docs/01-architecture.md) | The six layers, data flow, trust boundaries, deployment model |
| [`docs/02-control-authoring.md`](docs/02-control-authoring.md) | Controls as code in OSCAL |
| [`docs/03-policy-enforcement.md`](docs/03-policy-enforcement.md) | Compliance-to-Policy, Kyverno, OPA, admission and runtime |
| [`docs/04-trusted-delivery.md`](docs/04-trusted-delivery.md) | SBOM, SLSA, Sigstore, GitOps change control |
| [`docs/05-agent-governance.md`](docs/05-agent-governance.md) | AI gateway, agent registry, guardrails, tracing |
| [`docs/06-platform-substrate.md`](docs/06-platform-substrate.md) | Clusters, workloads, identity, observability |
| [`docs/07-evidence-and-audit.md`](docs/07-evidence-and-audit.md) | Continuous assessment, evidence ledger, audit packs |
| [`docs/08-regulatory-mapping.md`](docs/08-regulatory-mapping.md) | Control-to-technology mapping |
| [`docs/09-validation-approach.md`](docs/09-validation-approach.md) | GAMP 5, CSA, platform versus workload validation |
| [`docs/10-build-vs-buy.md`](docs/10-build-vs-buy.md) | Open source versus proprietary IP |
| [`docs/adr/`](docs/adr/) | Architecture decision records |
| [`reference/architecture.drawio`](reference/architecture.drawio) | The reference architecture diagram |

## Project files

| File | Purpose |
|---|---|
| [`LICENSE`](LICENSE) | Apache License 2.0 |
| [`NOTICE`](NOTICE) | Copyright and sponsorship notice |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute, including commit sign-off |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |
| [`GOVERNANCE.md`](GOVERNANCE.md) | Roles, decisions, and the open-core boundary |
| [`MAINTAINERS.md`](MAINTAINERS.md) | Who reviews and merges |
| [`SECURITY.md`](SECURITY.md) | How to report vulnerabilities |
| [`ROADMAP.md`](ROADMAP.md) | Planned phases |
| [`CHANGELOG.md`](CHANGELOG.md) | Notable changes |

## Contributing

Contributions are welcome: control mappings, policy templates, integrations, documentation, and issues. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`ROADMAP.md`](ROADMAP.md), and see [`GOVERNANCE.md`](GOVERNANCE.md) for how decisions are made and how to become a maintainer. All participants follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md). Do not open public issues for security problems.

## What it is not

The Fabric generates and maintains evidence. It does not replace the quality sign-off or the validation decision. That separation matches the risk-based assurance approach in GAMP 5 Second Edition and the FDA Computer Software Assurance (CSA) guidance. See [`docs/09-validation-approach.md`](docs/09-validation-approach.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
