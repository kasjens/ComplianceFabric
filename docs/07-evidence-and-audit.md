# Evidence, assessment, and audit

This layer turns platform state into audit-ready evidence and produces the documents an auditor or quality reviewer asks for, on demand.

## Continuous assessment

Policy results, image attestations, drift status, and agent traces are collected continuously and scored against the controls. Compliance-to-Policy normalizes engine results into OSCAL assessment results, so each data point references the control it bears on. Assessment is a constant background process, not an audit-time scramble.

**Implementation status:** seven producers feed the ledger today. `fabric evidence` derives change-control records from pull requests (see `04-trusted-delivery.md`); `fabric policy-report <report-json-file> <policies-dir>` turns a Kyverno PolicyReport into evidence records, mapping each result's policy back to the controls it enforces via the policy library's `fabric.control-id` annotations (a pass is satisfied, a fail, error, or warn is not-satisfied); `fabric drift <argo-apps-json-file> <control-id>` turns Argo CD application sync status into drift evidence (Synced is satisfied, OutOfSync is not-satisfied); `fabric trace <traces-json-file> <registry-dir> <control-id>` turns a gateway interaction log into agent-governance evidence, judging each interaction against the agent registry (satisfied only when the agent used its registered prompt and tools, off-policy otherwise; see `05-agent-governance.md`); `fabric eval-gate <eval-run-file> <gate-file> <control-id>` turns an agent version's evaluation results through the promotion gate into evidence (satisfied when the version would promote, not-satisfied when the gate blocks it); `fabric provenance <provenance-json-file> <expected-builder-id> <control-id>` turns a SLSA build-provenance attestation into evidence (satisfied when the artifact was built by the expected trusted builder, not-satisfied otherwise; see `04-trusted-delivery.md`); and `fabric sbom <sbom-json-file> <policy-file> <control-id>` turns a CycloneDX SBOM into evidence by screening the image's component inventory against a banned-components policy (a clean, non-empty inventory is satisfied; an empty inventory or any prohibited component is not-satisfied; see `04-trusted-delivery.md`). Collection now runs continuously as well as on invocation: `fabric collect <config-file> --ledger <path>` polls a declarative set of these sources on an interval, runs the same producers behind a shared `internal/collect` registry, and appends only state changes to the ledger (event-log dedup), so a stable control does not write a "still satisfied" row every tick.

## The evidence ledger

Evidence is written to an append-only, tamper-evident store. No component, including the Fabric's own operators, can rewrite history. Each record is keyed to a control identifier and a timestamp, and where it concerns an artifact it references the transparency-log entry for that artifact. The append-only property is what makes the evidence defensible: a reviewer can trust that it was not edited to pass.

The ledger achieves this by chaining: each stored entry carries a SHA-256 hash over the previous entry's hash and the record itself, so the entries form a linked chain. Mutating, deleting, or reordering any stored record breaks the chain, and `fabric ledger verify` detects the break. Records are persisted as one JSON object per line (JSON Lines).

## Data model

The minimum shape of an evidence record:

```json
{
  "control-id": "annex11-9-audit-trail",
  "subject": "cluster/prod-eu/ns/mes",
  "result": "satisfied",
  "observed-at": "2026-06-06T09:14:00Z",
  "source": "kyverno/require-audit-logging",
  "artifact-ref": "sha256:1f2e3d4c5b6a7980",
  "evidence": { "policy-report": "..." }
}
```

**Implementation status:** the first producer of these records is `fabric evidence`, which keys a GitOps change-control record to `annex11-10-change-control` (`control-id`, `subject`, `result`, `observed-at`, `source`, with the pull request embedded as the raw evidence). Records are emitted to stdout, and `fabric evidence --ledger <path>` also appends them to the append-only ledger described above; `fabric ledger verify <path>` confirms the chain is intact. `fabric ledger assess <path>` normalizes the stored records into an OSCAL assessment-results document — one finding per record, each tracing back to the control it bears on, the same model `fabric assess` emits — so evidence and design-time coverage share one shape. All seven producers now ship (change-control, policy reports, drift, agent traces, eval-gate, SLSA provenance, and SBOM content). The optional `artifact-ref` field above is now carried too: `fabric provenance` records the subject artifact's content digest (`sha256:<hex>`) and `fabric sbom` records the scanned image's digest, so a content or provenance record links back to the exact artifact — and thus to its transparency-log entry, since a transparency log is indexed by that same digest.

## Reporting

Two outputs sit on top of the ledger:

- A posture dashboard showing live control coverage, current gaps, and trend. This is the day-to-day view for platform and quality teams. `fabric ledger posture <path>` is the first cut: it rolls the ledger up per control to the latest observed result (latest record wins), how many times the control has been observed, and how many of those were lapses, exiting non-zero when any control currently has an open gap. A live dashboard surface over this rollup now ships: `fabric serve <ledger-path>` runs a read-only HTTP dashboard (`internal/dashboard`) that re-reads the ledger on every request and renders the rollup as an HTML table (gaps highlighted) plus a machine-readable `/posture.json` with a `{total, satisfied, gaps}` summary, so it reflects what `fabric collect` appends in real time. The *trend* view (coverage over time) ships too: `posture.TrendOf` replays the append-only ledger into a satisfied/total-per-moment series, surfaced as an inline-SVG sparkline on the dashboard and as a machine-readable `/trend.json` (`{"points":[{at, total, satisfied}]}`) a monitor can chart. Because the ledger is an event log of state changes, the trend is a faithful history rather than a sampled approximation.
- On-demand audit packs generated from the ledger: installation, operational, and performance qualification evidence (IQ/OQ/PQ), the Annex 11 audit trail, Part 11 records, and the EU AI Act technical file for agents. Each pack is assembled from records already collected, not written from scratch.

Because every record is tied to a control, a pack is a query over the ledger, not a manual document-gathering exercise. That is the source of the validation-effort reduction the design targets. The posture rollup is distinct from `fabric report`, which shows design-time coverage (is a control mapped to a policy at all); posture answers what the evidence has actually observed over time.
