# Roadmap

This roadmap shows the order the project plans to build in. It is a direction, not a set of dates, and it changes as contributors join and priorities shift. Open an issue to propose a change.

The phases follow the six layers in [`docs/01-architecture.md`](docs/01-architecture.md), built from the foundation up so each phase produces something usable on its own.

## Phase 0: Documentation and design (current)

- Reference architecture and layer documentation.
- Architecture decision records for the core choices.
- Open-core governance and contribution model.

## Phase 1: Controls as code and enforcement

- A first GxP OSCAL profile covering an Annex 11 and Part 11 control subset.
- Compliance-to-Policy integration that generates Kyverno policy from the profile.
- Admission and runtime enforcement for the mapped controls.
- Assessment results emitted in OSCAL.

## Phase 2: Trusted delivery and change control

- SBOM and SLSA provenance in the reference pipeline.
- Sigstore signature verification at admission.
- Change-control evidence from GitOps pull-request and merge records.

## Phase 3: Evidence and reporting

- An append-only evidence ledger keyed to control identifiers.
- Continuous assessment across the mapped controls.
- A posture view of live control coverage.

## Phase 4: AI agent governance

- Agent and prompt/tool registry as versioned artifacts.
- Gateway policy and interaction tracing.
- Evaluation gates before promotion.

## Phase 5: Cross-sector profiles

- DORA and NIS2 profiles that reuse the same engine and evidence base.
- ISO 42001 and EU AI Act mappings for the agent layer.

## Outside the open core

Audit-pack and validation-report generation, certified GxP control packs, and a hosted control plane are part of the commercial layer described in [`GOVERNANCE.md`](GOVERNANCE.md). They are listed here so the boundary is clear, not because they are planned for this repository.
