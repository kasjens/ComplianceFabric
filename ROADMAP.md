# Roadmap

This roadmap shows the order the project plans to build in. It is a direction, not a set of dates, and it changes as contributors join and priorities shift. Open an issue to propose a change.

The phases follow the six layers in [`docs/01-architecture.md`](docs/01-architecture.md), built from the foundation up so each phase produces something usable on its own.

> **Implementation review (2026-06-06).** Phases 0–4 were audited against the committed code, tests, and control data. Ground truth: `go test ./...`, `go vet`, and `gofmt -l` are all clean, the build is stdlib-only (no external dependencies), and `fabric validate`/`assess` pass on the shipped controls. The net-new engine (controls, five evidence producers, ledger, registry, eval gate) is fully implemented and test-covered. Two claims were corrected as overstated: the Sigstore admit path is **not** exercised in CI, and the SBOM/SLSA reference pipeline is **not started**. The Phase 1 kind-cluster admission proof, previously flagged as not reproducible, has since been closed: a committed e2e harness (`test/e2e/admission.sh`) now reproduces the deny/admit/PolicyReport proof and runs as a kind-based CI job. Each phase below carries a dated review note.

## Phase 0: Documentation and design (done)

- Reference architecture and layer documentation.
- Architecture decision records for the core choices.
- Open-core governance and contribution model.

**Review (2026-06-06): complete, verified.** 11 layer docs (`docs/00`–`docs/10`), 7 ADRs (`docs/adr/0001`–`0007`), and the full governance set (LICENSE, NOTICE, GOVERNANCE, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, MAINTAINERS) are present. The reference architecture diagram (`reference/architecture.drawio`) ships. No gaps.

## Phase 1: Controls as code and enforcement (done)

- A first GxP OSCAL profile covering an Annex 11 and Part 11 control subset.
- Policy composition from the profile. An interim native composer (`fabric generate`) fills this role today; it is swappable for Compliance-to-Policy without changing the control data, which already follows the OSCAL rule_set convention C2P expects.
- Admission and runtime (continuous) enforcement for the mapped controls via the Kyverno policy library, with `fabric.control-id` traceability, proven on a live cluster by a committed, reproducible e2e harness wired into CI.
- The `fabric assess` command reports control coverage and emits OSCAL assessment-results.

**Review (2026-06-06): complete, verified end-to-end.** Verified: the GxP profile validates, `fabric generate` composes the policy set, `fabric policies` confirms `fabric.control-id` traceability across the five-policy library, and `fabric assess --strict` emits OSCAL assessment-results — all run in CI. The earlier caveat is now closed: [`test/e2e/admission.sh`](test/e2e/admission.sh) is a committed, reproducible harness (run as a kind-based CI job) that stands up Kyverno, applies the Phase 1 policy library, and asserts all three enforcement behaviours — a non-compliant Pod is **denied** at admission, a compliant Pod is **admitted**, and Kyverno's background scan produces a **PolicyReport** that `fabric policy-report` turns into satisfied evidence the ledger accepts and verifies (runtime/continuous enforcement). The image-signature policy is excluded from this harness on purpose: it needs Sigstore/cosign and belongs to Phase 2. Phase 1 is fully done.

## Phase 2: Trusted delivery and change control (in progress)

- SBOM and SLSA provenance in the reference pipeline. **Partial:** the evidence side is built — `fabric provenance` turns a verified SLSA provenance attestation into control evidence keyed to `cfr-part-11-10a-system-validation` (a non-Kyverno `supply-chain` component), TDD-tested from a fixture. The *generation* side (syft SBOM + cosign attest/sign in CI, bound to the image digest) is **not yet wired** — it needs cosign/syft and is best done in CI.
- Sigstore signature verification at admission. **Partial:** the keyless `verify-image-signatures` Kyverno policy is authored and mapped to `cfr-part-11-10a-system-validation`. No automated cluster proof is committed: CI does not stand up a kind cluster or run cosign, so neither the deny path nor the admit path is exercised in CI.
- Change-control evidence from GitOps pull-request and merge records. **Done:** the `fabric evidence` command derives an attributable, time-stamped change-control record from a pull request, flags invalid authorizations, and emits an evidence-ledger record keyed to the `annex11-10-change-control` control. Records persist to the append-only ledger via `fabric evidence --ledger`, and `fabric ledger assess` normalizes them into OSCAL assessment-results (see Phase 3).

**Review (2026-06-06): genuinely in progress; two items were overstated.** *Change-control evidence is done and verified* (`internal/evidence`, CLI- and unit-tested). *Sigstore* was previously marked "deny path proven on kind, admit path exercised in CI" — corrected above: the policy exists but `ci.yml` runs only Go checks and the `fabric` commands, with no kind cluster and no cosign step, so there is no committed automated signature proof. *SBOM/SLSA* has no implementation — `reference/` holds only the architecture diagram, and no syft/cosign-attest pipeline is committed; it is blocked locally (no cosign/syft) and best done in CI. *Update (2026-06-06): the SBOM/SLSA evidence producer is now built* — `fabric provenance` consumes a verified SLSA provenance attestation and keys it to `cfr-part-11-10a-system-validation` via a `supply-chain` component (TDD-tested from a fixture). What remains for Phase 2 is the live, CI-side proof: a job (or e2e script) that creates a kind cluster, installs Kyverno, signs and attests a test image with the GitHub Actions OIDC identity, and asserts the admit/deny behaviour plus the generated SBOM/provenance — all of which needs cosign/syft and the CI signing identity.

## Phase 3: Evidence and reporting (in progress)

- An append-only evidence ledger keyed to control identifiers. **Done:** the `internal/ledger` store chains records by hash (tamper-evident, JSON Lines); `fabric evidence --ledger` appends and `fabric ledger verify` checks the chain.
- Continuous assessment across the mapped controls. **Done (collection on invocation):** `fabric ledger assess` normalizes the ledger into OSCAL assessment-results, and six producers feed it: change-control from pull requests (`fabric evidence`), Kyverno policy results (`fabric policy-report`), GitOps drift from Argo CD sync status (`fabric drift`), agent interaction traces (`fabric trace`), agent eval-gate verdicts (`fabric eval-gate`), and SLSA build-provenance attestations (`fabric provenance`). Remaining is collecting evidence continuously rather than on invocation.
- A posture view of live control coverage. **Done:** `fabric ledger posture` rolls the ledger up per control (latest observed result, observation count, lapses); remaining is the live dashboard surface over it.

**Review (2026-06-06): substantially done; the heading and producer list were stale.** Verified: the hash-chained ledger, `fabric ledger verify`/`assess`/`posture`, and all six producers are implemented and test-covered. *Corrections:* the phase now carries an "(in progress)" marker for consistency; the producer count is updated from three to six (agent traces and eval-gate verdicts from Phase 4, and the SLSA build-provenance producer from Phase 2, all also feed the Phase 3 ledger); and the image-attestation source is removed from the remaining list since `fabric provenance` ships. Honestly still open: continuous (vs on-invocation) collection, and a live dashboard surface over the posture rollup.

## Phase 4: AI agent governance (in progress)

- Agent and prompt/tool registry as versioned artifacts. **Done:** the `internal/registry` package models agents, prompts, and tools as versioned artifacts, and `fabric registry validate` checks versioning, agent ownership, reference resolution, and duplicate ids. A starter registry lives under `registry/`.
- Gateway policy and interaction tracing. **Done (tracing):** `fabric trace` is a fourth evidence producer that judges each gateway interaction against the registry's qualified surface (an undeclared prompt or tool, or an unregistered agent, is off-policy) and keys records to `eu-ai-act-12-record-keeping`, feeding the same ledger. The runtime gateway that enforces policy inline (rather than evaluating its log after the fact) remains.
- Evaluation gates before promotion. **Done:** the `internal/eval` package models the promotion gate as authoritative policy (required suites and a failure budget), and `fabric eval-gate` is a fifth evidence producer that records whether a version was cleared to ship, keyed to `eu-ai-act-15-accuracy-robustness`.

**Review (2026-06-06): the implemented (data-and-logic) scope is done and accurate.** Verified: `internal/registry` + `fabric registry validate`, `internal/eval` + `fabric eval-gate`, and the `fabric trace` producer are all implemented and test-covered; the new `eu-ai-act` catalog controls validate and assess satisfied; a starter registry ships under `registry/`. The one open item is correctly stated: the inline runtime gateway that enforces policy at request time (rather than evaluating its interaction log after the fact) — it needs a live gateway and is not reproducible from fixtures, so it is out of scope for the test-first work done here. Minor hardening option: the Phase 4 CLI commands are covered by `go test` but, unlike the Phase 1 commands, are not invoked as dedicated CI steps.

## Phase 5: Cross-sector profiles

- DORA and NIS2 profiles that reuse the same engine and evidence base.
- ISO 42001 and EU AI Act mappings for the agent layer.

## Outside the open core

Audit-pack and validation-report generation, certified GxP control packs, and a hosted control plane are part of the commercial layer described in [`GOVERNANCE.md`](GOVERNANCE.md). They are listed here so the boundary is clear, not because they are planned for this repository.
