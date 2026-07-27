# ADR 0009: Fail closed — absence of evidence is not evidence of compliance

## Status

Accepted.

## Context

A security and compliance review of the engine found the same defect shape in six independent places, written by different hands at different times:

| Input | Behaviour before |
|---|---|
| A message body shape the screener did not recognise | guardrail **allowed** |
| A crosswalk mapping with zero anchors | citation **satisfied** |
| A control whose rule resolved to an empty check id | control **satisfied** |
| A release manifest whose producers yielded zero records | release **cleared** |
| An evaluation gate with an empty results list | version **cleared** |
| A posture record with no usable timestamp | stale green **preserved** |

Each is defensible in isolation and each was written by someone doing something reasonable: seed the result as satisfied and let the loop disprove it; skip content you cannot parse; treat a missing optional field as a zero value. Together they form a pattern — **the system reported "satisfied" precisely when it knew least.**

That is the worst possible failure direction for this product. A compliance engine that under-reports is annoying; one that over-reports manufactures false audit evidence, and the people relying on it have no way to tell.

The common root is that "no signal" was being conflated with "no problem". In every case the code had an opportunity to distinguish *checked and passed* from *never checked*, and did not.

## Decision

**Fail closed. Absence of evidence is never evidence of compliance.**

Concretely, for any code in this repository:

- An empty input set — no anchors, no records, no results, no checks — is **not satisfied**. Never seed a result as satisfied and rely on a loop to disprove it; seed it as not-satisfied and let evidence earn the pass.
- Content that cannot be parsed, decoded, or recognised is **blocked**, not skipped. A screener that returns "nothing to see" for a shape it does not understand is not screening.
- A missing value is **not** a usable zero. An absent timestamp is not 1970; an unresolved check id is not a check. Where a value must be inferred, mark it as inferred so nothing downstream can mistake it for a measurement.
- Every review of a change to this engine asks: **"what does this do with empty input?"** That question, applied to any of the six sites above, would have caught it.

Where failing closed is genuinely wrong — a post-hoc re-derivation of a historical trace that legitimately lacks a field, where denying would manufacture a lapse that never happened — the leniency is **explicit, narrow, and named**, not the accidental result of a zero value flowing through.

## Consequences

- Some commands that previously exited 0 now exit 1. That is the fix, not a regression: they were passing on no evidence. Anything that starts failing was already not proving what it claimed.
- Bad or incomplete input surfaces loudly and early, at the cost of some operator friction. This is the right trade for a system whose output is audit evidence.
- The rule is testable, and is tested: the regression suite pins the empty-input behaviour of each site so the pattern cannot quietly return.
- This ADR is deliberately broad. It binds future contributions, including ones in packages that do not exist yet — the six sites were independent, so a narrower rule would not have prevented any of them.
