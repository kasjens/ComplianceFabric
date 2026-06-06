# Evidence, assessment, and audit

This layer turns platform state into audit-ready evidence and produces the documents an auditor or quality reviewer asks for, on demand.

## Continuous assessment

Policy results, image attestations, drift status, and agent traces are collected continuously and scored against the controls. Compliance-to-Policy normalizes engine results into OSCAL assessment results, so each data point references the control it bears on. Assessment is a constant background process, not an audit-time scramble.

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
  "artifact-ref": "rekor:index/884215",
  "evidence": { "policy-report": "..." }
}
```

**Implementation status:** the first producer of these records is `fabric evidence`, which keys a GitOps change-control record to `annex11-10-change-control` (`control-id`, `subject`, `result`, `observed-at`, `source`, with the pull request embedded as the raw evidence). Records are emitted to stdout, and `fabric evidence --ledger <path>` also appends them to the append-only ledger described above; `fabric ledger verify <path>` confirms the chain is intact. Still to come: the OSCAL assessment-results form, and producers for the other evidence sources (policy reports, attestations, drift, agent traces).

## Reporting

Two outputs sit on top of the ledger:

- A posture dashboard showing live control coverage, current gaps, and trend. This is the day-to-day view for platform and quality teams.
- On-demand audit packs generated from the ledger: installation, operational, and performance qualification evidence (IQ/OQ/PQ), the Annex 11 audit trail, Part 11 records, and the EU AI Act technical file for agents. Each pack is assembled from records already collected, not written from scratch.

Because every record is tied to a control, a pack is a query over the ledger, not a manual document-gathering exercise. That is the source of the validation-effort reduction the design targets.
