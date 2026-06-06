# ADR 0006: Open Cluster Management for the cluster fleet

## Status

Accepted (reference design).

## Context

Regulated estates run across multiple clusters and regions. The same controls must apply uniformly everywhere, yet each cluster needs its own assessment results so posture can be shown per cluster and in aggregate. Sovereign-cloud requirements also mean evidence should stay in the user's environment.

## Decision

Manage clusters as a fleet with Open Cluster Management (OCM). One authored set of controls and policies distributes across every managed cluster. Each cluster reports its own assessment results back, which the evidence layer renders both per cluster and aggregated.

## Consequences

- One control set applies fleet-wide, so controls are authored once rather than per cluster.
- Per-cluster assessment results match the evidence layer's posture model and support sovereign-cloud deployments where data stays local.
- A hub/management plane is added to the architecture and must itself be operated and qualified.
- Fleet rollout of a control change becomes a first-class concern, which reinforces the GitOps change-control flow in ADR 0005.
