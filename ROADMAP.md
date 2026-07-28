# Roadmap

This roadmap shows the order the project plans to build in. It is a direction, not a set of dates, and it changes as contributors join and priorities shift. Open an issue to propose a change.

The phases follow the six layers in [`docs/01-architecture.md`](docs/01-architecture.md), built from the foundation up so each phase produces something usable on its own.

## Where the project is today

**Current release: [`v0.1.0`](https://github.com/kasjens/ComplianceFabric/releases/tag/v0.1.0)** — the first tagged release, gated on its own SBOM and SLSA provenance evidence, with the artifacts and the evidence ledger signed keylessly and verified in the same job.

| Phase | State | What is actually proven |
|---|---|---|
| 0 — Documentation and design | **Done** | 11 layer docs, 10 ADRs, full governance set |
| 1 — Controls as code and enforcement | **Done** | Admission deny/admit and a PolicyReport, on a live kind cluster in CI |
| 2 — Trusted delivery and change control | **Done** | Keyless signature verification at admission, SBOM + provenance evidence, release gate |
| 3 — Evidence and reporting | **Done** | Hash-chained ledger, seven producers, posture rollup, live dashboard, continuous collector |
| 4 — AI agent governance | **In progress** | Registry, gateway, live proxy, eval gates and tracing all ship and are proven end to end. **Open: a reference deployment.** |
| 5 — Cross-sector profiles | **In progress** | DORA, NIS2 and ISO 42001 crosswalks ship and now run against a real ledger in CI. **Open: the remaining integration proofs.** |

Every CLI subcommand runs as the real binary in CI, the unit suite runs with `-race` on Linux and Windows, and five end-to-end suites cover admission, the inline gateway, the live proxy, SBOM content and the release gate.

## What's next

In the order the project intends to take them:

1. **A reference deployment for the gateway (closes Phase 4).** The enforcement logic is proven against a fake upstream in CI; what is missing is a worked, deployable example — manifests, a sidecar or mesh pattern, and the operational posture [ADR-0008](docs/adr/0008-gateway-trust-model.md) assumes. Until that exists, "route all agent traffic through the gateway" is an instruction without an implementation.
2. **The remaining Phase 5 integration proofs.** `fabric crosswalk` now runs in CI against a real ledger, which was the specific gap that reopened the phase. It stays open until the rest is proven the same way.
3. **External ledger anchoring** ([ADR-0010](docs/adr/0010-ledger-anchoring-and-its-limits.md), step 4). The checkpoint sidecar detects tail truncation, but the ledger cannot resist a writer with access to its host. Signed checkpoints, or publishing the head hash to a transparency log, is what would change that — and nothing will claim it before it lands.
4. **Evidence correction as appended dispute.** A control that was misconfigured records a false `satisfied`, and that entry stays in the chain forever. Today the only correction is re-observation: a later differing record for the same `(control-id, subject)` wins the posture rollup, but the original is untouched, and a reviewer reading the raw chain sees both with equal standing. The append-only property is right and is not up for negotiation — the missing piece is a correction that is *itself* an appended entry, referencing the hash of the record it disputes, so the dispute is visible in the chain rather than inferred at query time. This needs stable record identity first (`evidence.Record` carries no id), and an ADR on whether a disputed record still counts toward `ControlPosture.Lapses`, which is monotonic today. Tracked in [#4](https://github.com/kasjens/ComplianceFabric/issues/4).
5. **Supply-chain residuals.** Actions, tool versions and scanned images are pinned; the syft *install script* is still fetched from its main branch, so what is installed is pinned but the installer is not.

### A note on how this roadmap is written

Phases are marked done only when an **integration proof** exists — a committed harness that runs the real binary in CI, not a unit test. Phase 5 was marked done once and flipped back when it turned out its headline command had never run outside `go test`. Where earlier claims ran ahead of their evidence, the correction is kept rather than edited away — in [`docs/roadmap-history.md`](docs/roadmap-history.md), so this page stays a statement of position rather than a changelog. A roadmap that quietly rewrites its own history is worth less than one that shows its corrections.
## The phases

Each phase lists what it delivers and where it stands. The dated review notes that used to sit
here — including the several that record a claim running ahead of its evidence, and how it was
corrected — are kept in [`docs/roadmap-history.md`](docs/roadmap-history.md).

## Phase 0: Documentation and design (done)

- Reference architecture and layer documentation — 11 layer docs, plus the architecture diagram in `reference/`.
- Architecture decision records for the core choices — 10 ADRs.
- Open-core governance and contribution model.

## Phase 1: Controls as code and enforcement (done)

- A GxP OSCAL profile covering an Annex 11 and 21 CFR Part 11 control subset.
- Policy composition from the profile (`fabric generate`). An interim native composer fills this role today; it is swappable for Compliance-to-Policy without changing the control data, which already follows the OSCAL rule_set convention C2P expects.
- Admission and runtime enforcement via the Kyverno policy library with `fabric.control-id` traceability.
- `fabric assess` reports control coverage and emits OSCAL assessment-results.

**Proven by** [`test/e2e/admission.sh`](test/e2e/admission.sh) on a live kind cluster in CI: a non-compliant Pod is denied, a compliant one is admitted, and Kyverno's background scan produces a PolicyReport that becomes evidence the ledger accepts.

## Phase 2: Trusted delivery and change control (done)

- SBOM and SLSA provenance evidence producers (`fabric sbom`, `fabric provenance`).
- Sigstore keyless signature verification at admission.
- Change-control evidence from GitOps pull-request and merge records (`fabric evidence`).
- A release evidence gate (`fabric release-gate`) binding evidence generation into the release pipeline itself.

**Proven by** four CI jobs: keyless deny/admit against the production policy on a kind cluster, SBOM content from a real syft scan, the release gate over a genuine SBOM plus provenance, and the release workflow itself, which gated and signed `v0.1.0`.

*Note: cosign is pinned to v2 in the admission harnesses because cosign v3's default bundle format is unreadable by the cosign library in Kyverno v1.11.5.*

## Phase 3: Evidence and reporting (done)

- An append-only, hash-chained evidence ledger keyed to control identifiers, with a checkpoint sidecar so tail truncation is detectable ([ADR-0010](docs/adr/0010-ledger-anchoring-and-its-limits.md)).
- Seven evidence producers feeding it: change control, Kyverno policy reports, GitOps drift, agent traces, eval-gate verdicts, SLSA provenance and SBOM content.
- Continuous collection (`fabric collect`) that polls declarative sources and appends only state changes.
- OSCAL assessment-results, a posture rollup and a coverage trend, served by a live dashboard (`fabric serve`) with `/posture.json` and `/trend.json`.

**Out of the open core, deliberately:** audit-pack and validation-report generation (IQ/OQ/PQ, Annex 11 audit trail, Part 11 records, EU AI Act technical file) is a commercial concern — see [Outside the open core](#outside-the-open-core).

## Phase 4: AI agent governance (in progress)

- Agent, prompt and tool registry as versioned artifacts (`fabric registry validate`). **Done.**
- An inline gateway (`fabric gateway`) and a live LLM/MCP traffic proxy (`fabric gateway-proxy`) enforcing authenticated agent identity, the model and tool allow-list, content guardrails on both request and response — including incremental screening of streamed (SSE) responses — and per-agent rate and cost budgets. **Done.**
- Evaluation gates before promotion (`fabric eval-gate`). **Done.**
- Interaction tracing (`fabric trace`), consuming the gateway's own log or an OpenTelemetry OTLP/JSON export. **Done.**

**Proven by** [`test/e2e/gateway.sh`](test/e2e/gateway.sh) and [`test/e2e/gateway-proxy.sh`](test/e2e/gateway-proxy.sh), which drive the real binaries over live HTTP and assert forwarding, every block path, response screening, and that a secret split across streamed events is cut mid-stream. The proxy's own log is then fed through `fabric trace` into a ledger that verifies.

**Still open: a reference deployment.** The enforcement logic is proven against a fake upstream; what does not exist is a worked, deployable example — manifests, a sidecar or mesh pattern, and the operational posture [ADR-0008](docs/adr/0008-gateway-trust-model.md) assumes. Until it does, "route all agent traffic through the gateway" is an instruction without an implementation.

## Phase 5: Cross-sector profiles (in progress)

- DORA and NIS2 profiles that reuse the same engine and evidence base. **Done.**
- ISO 42001 and EU AI Act mappings for the agent layer. **Done** — the ISO 42001 crosswalk is answered by the EU AI Act eval-gate and record-keeping controls the agent layer already evidences.

A crosswalk maps a target-sector citation onto the controls the Fabric already enforces, and `crosswalk.Apply` rolls existing evidence up under those citations — a citation is satisfied only when every anchor behind it is. Crosswalks are first-class control-tree artifacts, so `fabric validate` catches a typo'd anchor rather than letting it silently make a citation unsatisfiable.

**Proven by** [`test/e2e/commands.sh`](test/e2e/commands.sh), which applies every committed crosswalk to a real ledger built from real evidence for every anchor control they name, and asserts that a crosswalk over an *empty* ledger reports not-satisfied rather than claiming compliance by vacuity.

**Still open: the remaining integration proofs.** This phase was marked done once and flipped back when it turned out its headline command had never run outside `go test`. It stays open until the rest is proven the same way.

## Outside the open core

Audit-pack and validation-report generation, certified GxP control packs, and a hosted control plane are part of the commercial layer described in [`GOVERNANCE.md`](GOVERNANCE.md). They are listed here so the boundary is clear, not because they are planned for this repository.
