# ADR 0005: GitOps as the change-control mechanism

## Status

Accepted (reference design).

## Context

Annex 11 and Part 11 expect an attributable, time-stamped record of who authorized each change to a computerised system, and continuous assurance that the qualified state still holds. A change process that lives outside the platform is hard to evidence and easy to bypass.

## Decision

Use GitOps for change control. Git holds the desired state of the platform, and a reconciler keeps clusters matching it. Every change is a pull request: its reviewer approvals and merge timestamp are the change-control record. Drift between live state and Git is detected continuously.

The specific reconciler (Argo CD or Flux) is intentionally left open. Both satisfy the requirements above, so the choice is deferred to the deployment, and control packs must not depend on tool-specific features.

## Consequences

- A reviewed, approved, merged PR is an electronic record of who authorized a change and when, which is what an Annex 11 or Part 11 reviewer asks for.
- Drift detection turns "is the qualified state still intact?" into a continuous check rather than a periodic audit.
- Paired with the artifact's transparency-log entry (ADR 0003), a merge links a specific authorized change to a specific verified build.
- Leaving the reconciler open avoids premature lock-in but means the project tests against the GitOps contract, not a single tool's extensions.
