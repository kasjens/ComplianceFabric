# Regulated Kubernetes platform

The substrate is the platform the Fabric runs over and qualifies. The Fabric does not replace it; it controls and evidences it.

## Cluster fleet

Clusters are managed as a fleet through Open Cluster Management, so one set of controls and policies applies across clusters and regions. Each cluster reports its own assessment results, which lets the evidence layer show posture per cluster and in aggregate.

## Regulated workloads

The workloads are the regulated applications and their AI agents: manufacturing execution systems, laboratory information management systems, electronic quality management systems, and the agents that act on them. These are what the controls protect and what validation ultimately concerns.

## Identity and access

Access uses OIDC and least-privilege RBAC. Identity is also the basis for the electronic-signature property of change control: an approval in Git is attributable to a named identity. Service identities, including the build pipeline and the agent gateway, are first-class and scoped to what they need.

## Observability

OpenTelemetry, logs, and metrics serve two purposes at once. They run the platform, and they feed the evidence layer. Treating observability data as evidence, not just operational telemetry, is what keeps the assessment continuous rather than periodic.

## The qualified baseline

The platform has a defined, version-controlled baseline: the cluster configuration, the installed controllers, and the policies in force. Drift from this baseline is detected continuously. The baseline is what gets qualified once, so that workloads on top of it inherit a known-good foundation rather than re-qualifying the platform each time. This separation is the subject of `09-validation-approach.md`.
