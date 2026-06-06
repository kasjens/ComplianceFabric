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

### Changed

- Renamed the project from "GxP Compliance Fabric" to "Compliance Fabric" across documentation and metadata.
