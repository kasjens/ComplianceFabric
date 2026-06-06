# Roadmap

This roadmap shows the order the project plans to build in. It is a direction, not a set of dates, and it changes as contributors join and priorities shift. Open an issue to propose a change.

The phases follow the six layers in [`docs/01-architecture.md`](docs/01-architecture.md), built from the foundation up so each phase produces something usable on its own.

## Phase 0: Documentation and design (done)

- Reference architecture and layer documentation.
- Architecture decision records for the core choices.
- Open-core governance and contribution model.

## Phase 1: Controls as code and enforcement (done)

- A first GxP OSCAL profile covering an Annex 11 and Part 11 control subset.
- Policy composition from the profile. An interim native composer (`fabric generate`) fills this role today; it is swappable for Compliance-to-Policy without changing the control data, which already follows the OSCAL rule_set convention C2P expects.
- Admission enforcement for the mapped controls via the Kyverno policy library, with `fabric.control-id` traceability proven on a kind cluster. Runtime (continuous) enforcement remains.
- The `fabric assess` command reports control coverage; OSCAL assessment-results output remains.

## Phase 2: Trusted delivery and change control (in progress)

- SBOM and SLSA provenance in the reference pipeline.
- Sigstore signature verification at admission. **Done:** keyless `verify-image-signatures` policy; deny path proven on kind, admit path exercised in CI.
- Change-control evidence from GitOps pull-request and merge records. **Done:** the `fabric evidence` command derives an attributable, time-stamped change-control record from a pull request, flags invalid authorizations, and emits an evidence-ledger record keyed to the `annex11-10-change-control` control. Records persist to the append-only ledger via `fabric evidence --ledger`, and `fabric ledger assess` normalizes them into OSCAL assessment-results (see Phase 3).

## Phase 3: Evidence and reporting

- An append-only evidence ledger keyed to control identifiers. **Done:** the `internal/ledger` store chains records by hash (tamper-evident, JSON Lines); `fabric evidence --ledger` appends and `fabric ledger verify` checks the chain.
- Continuous assessment across the mapped controls. `fabric ledger assess` normalizes the ledger into OSCAL assessment-results, and three producers feed it: change-control from pull requests (`fabric evidence`), Kyverno policy results (`fabric policy-report`), and GitOps drift from Argo CD sync status (`fabric drift`). Remaining is the other sources (image attestations, agent traces) and collecting them continuously rather than on invocation.
- A posture view of live control coverage. **Done:** `fabric ledger posture` rolls the ledger up per control (latest observed result, observation count, lapses); remaining is the live dashboard surface over it.

## Phase 4: AI agent governance (in progress)

- Agent and prompt/tool registry as versioned artifacts. **Done:** the `internal/registry` package models agents, prompts, and tools as versioned artifacts, and `fabric registry validate` checks versioning, agent ownership, reference resolution, and duplicate ids. A starter registry lives under `registry/`.
- Gateway policy and interaction tracing. **Done (tracing):** `fabric trace` is a fourth evidence producer that judges each gateway interaction against the registry's qualified surface (an undeclared prompt or tool, or an unregistered agent, is off-policy) and keys records to `eu-ai-act-12-record-keeping`, feeding the same ledger. The runtime gateway that enforces policy inline (rather than evaluating its log after the fact) remains.
- Evaluation gates before promotion. **Done:** the `internal/eval` package models the promotion gate as authoritative policy (required suites and a failure budget), and `fabric eval-gate` is a fifth evidence producer that records whether a version was cleared to ship, keyed to `eu-ai-act-15-accuracy-robustness`.

## Phase 5: Cross-sector profiles

- DORA and NIS2 profiles that reuse the same engine and evidence base.
- ISO 42001 and EU AI Act mappings for the agent layer.

## Outside the open core

Audit-pack and validation-report generation, certified GxP control packs, and a hosted control plane are part of the commercial layer described in [`GOVERNANCE.md`](GOVERNANCE.md). They are listed here so the boundary is clear, not because they are planned for this repository.
