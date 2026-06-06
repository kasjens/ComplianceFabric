# Architecture

The Fabric is six layers stacked around one control loop. Authored controls flow down into enforcement and onto the platform; running state flows back up into evidence and reporting. The diagram in `reference/architecture.drawio` shows the full picture.

## The six layers

1. Control authoring. Controls as code in OSCAL, including a GxP set (GAMP 5, Annex 11, Part 11, ALCOA+) and cross-sector profiles (DORA, NIS2, ISO 42001, EU AI Act). See `02-control-authoring.md`.
2. Policy translation and enforcement. Controls compiled into Kubernetes policy and enforced at CI, admission, and runtime. See `03-policy-enforcement.md`.
3. Trusted delivery and change control. Signed, provenance-bearing artifacts and GitOps-driven change. See `04-trusted-delivery.md`.
4. AI agent governance. A gateway, an agent registry, guardrails, and tracing for every agent action. See `05-agent-governance.md`.
5. Regulated Kubernetes platform. The cluster fleet, regulated workloads, identity, and observability the Fabric runs over. See `06-platform-substrate.md`.
6. Evidence, assessment, and audit. Continuous assessment, an immutable evidence ledger, and on-demand audit packs. See `07-evidence-and-audit.md`.

## Data flow

The loop has two directions.

Downward (control to enforcement): an author commits an OSCAL change. Compliance-to-Policy compiles the affected controls into policy resources. GitOps syncs them to the target clusters. Admission and runtime controllers begin enforcing them.

Upward (state to evidence): policy results, image attestations, drift status, and agent traces are collected continuously, normalized into OSCAL assessment results, and written to the evidence ledger. The reporting layer renders them as posture dashboards and audit packs.

## Trust boundaries

- Authoring and policy source live in Git, which is the controlled record of intent. Write access is the highest-privilege boundary.
- The build and signing pipeline is a separate trust boundary. Its identity signs artifacts; admission trusts only that identity.
- The evidence ledger is append-only. No component, including operators, can rewrite history. This is what makes the evidence defensible.
- The AI gateway is the boundary for all agent traffic to models and tools. Nothing reaches a model or a tool outside it.

## Deployment model

The Fabric is delivered as a set of Kubernetes operators and controllers installed on the customer's clusters, plus a control plane for authoring and reporting. Customer data and evidence stay in the customer's environment, which supports sovereign-cloud requirements. The control plane holds control definitions, mappings, and report templates, not regulated data.

Multi-cluster fleets are managed through Open Cluster Management, so one set of controls applies across clusters and regions with per-cluster assessment results.
