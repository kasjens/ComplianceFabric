# Changelog

All notable changes to this project are recorded here. The format follows Keep a Changelog. The project moves to semantic versioning once it publishes releases.

## [Unreleased]

### Added

- Reference architecture and layer documentation (`docs/00` through `docs/10`).
- Architecture decision records 0001 through 0007, covering OSCAL, Kyverno, Sigstore, the open-core model, GitOps change control, Open Cluster Management, and the AI/MCP gateway.
- Reference architecture diagram (`reference/architecture.drawio`).
- Open-core project setup: license, notice, governance, contribution guide, code of conduct, security policy, roadmap, maintainers, and GitHub issue and pull-request templates.
- OSCAL controls layer: catalogs (Annex 11, 21 CFR Part 11), the pharma MES baseline profile, and component definitions expressed in the OSCAL rule_set convention so the data is Compliance-to-Policy compatible.
- `fabric` CLI (`cmd/fabric`) with `validate`, `report`, `assess`, `policies`, and `generate` commands; standard-library-only Go, developed test-first.
- Kyverno policy library under `policies/kyverno/` with `fabric.control-id` traceability, verified by the `policies` command and in CI.
- Native policy composer (`internal/generate`, `fabric generate`) as an interim stand-in for Compliance-to-Policy: it composes the deployable policy set for the selected controls. It is intentionally swappable for C2P and does not author policy.
- Sigstore keyless image-signature verification at admission (`policies/kyverno/verify-image-signatures.yaml`) mapped to the new `cfr-part-11-10a-system-validation` control. The deny path (unsigned image rejected) is proven on a kind cluster; the signed-image admit path is exercised in CI, which holds the signing identity.
- Change-control evidence extractor (`internal/evidence`) and `fabric evidence` command: derives an attributable, time-stamped change-control record (author, approvers, merge timestamp, merge commit) from `gh pr view --json` output, and flags records that are not valid authorized changes per Annex 11 / Part 11. Exits non-zero on findings so it can gate CI.
- The `annex11-10-change-control` control and a non-Kyverno `gitops` component that maps it to a `gitops-pr-evidence` check, selected in the pharma MES baseline. Coverage and assessment count it satisfied, while the Kyverno-only `policies` and `generate` commands ignore it.
- `fabric evidence <pr-json-file> <control-id>` emits a machine-readable evidence-ledger record keyed to the control (the `docs/07` data model), with the change record embedded as raw evidence; it exits non-zero when the change is not a valid authorization.
- Append-only, tamper-evident evidence ledger (`internal/ledger`): records are chained by a SHA-256 hash over the previous hash and the record, persisted as JSON Lines, so any later mutation, deletion, or reordering breaks the chain and is detectable.
- `fabric evidence ... --ledger <path>` appends the evidence record to a ledger (a flagged change is recorded too; the exit code still reflects findings), and `fabric ledger verify <path>` walks the chain and exits non-zero if it has been tampered with.
- `fabric ledger assess <path>` normalizes the ledger's evidence records into an OSCAL assessment-results document (one finding per record, control-id and status carried through) — the same model `fabric assess` emits — and exits non-zero when any finding is not-satisfied, so CI can gate on observed evidence.
- Control-posture rollup (`internal/posture`) and `fabric ledger posture <path>`: for each control, the latest observed result (latest record wins), how many times it has been observed, and how many of those were lapses. This is the day-to-day posture view for platform and quality teams, distinct from the design-time coverage `fabric report` shows; it exits non-zero when any control currently has an open gap.

### Changed

- Renamed the project from "GxP Compliance Fabric" to "Compliance Fabric" across documentation and metadata.
