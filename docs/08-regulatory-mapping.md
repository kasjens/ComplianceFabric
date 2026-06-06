# Regulatory mapping

This is the reference table from control families to the Fabric components that implement and evidence them. It is the artifact that lets a quality team see, per requirement, where the control lives and where the proof comes from.

## Life sciences (GxP)

| Requirement family | Fabric component | Evidence produced |
|---|---|---|
| GAMP 5 risk-based control | Control authoring (OSCAL profiles) | Profile scoping each control to the system |
| Annex 11 audit trail | Platform logging, evidence ledger | Time-stamped, append-only records |
| Annex 11 change control | GitOps PR flow | Reviewed, approved, merged change records |
| 21 CFR Part 11 electronic records | Evidence ledger (append-only) | Attributable, retained records |
| 21 CFR Part 11 electronic signatures | OIDC identity + PR approval | Named approver bound to each change |
| 21 CFR Part 11 access control | RBAC + admission policy | Enforced least-privilege, policy results |
| ALCOA+ data integrity | Evidence ledger + transparency log | Tamper-evident, complete, enduring evidence |
| Configuration management | GitOps desired state + drift detection | Baseline plus continuous drift status |

## AI-specific

| Requirement family | Fabric component | Evidence produced |
|---|---|---|
| EU AI Act Art. 11 technical documentation | Agent registry + tracing | Versioned config and interaction records |
| EU AI Act post-market monitoring | Interaction tracing + guardrails | Continuous runtime monitoring records |
| ISO 42001 AI management system | Agent registry + assessment | Inventory, risk, and monitoring records |
| NIST AI RMF (Govern/Map/Measure/Manage) | Control authoring + agent governance | Control coverage mapped to the four functions |
| EU GMP Annex 22 (AI in GMP) | Agent governance layer | AI control and validation evidence |

## Finance and cross-sector

| Requirement family | Fabric component | Evidence produced |
|---|---|---|
| DORA operational resilience | Platform substrate + observability | Resilience controls and telemetry |
| DORA change and incident records | GitOps + evidence ledger | Change and incident evidence |
| NIS2 technical security controls | Admission and runtime policy | Enforced controls and policy results |
| Supply-chain integrity (cross-sector) | SBOM, SLSA, Sigstore | Signed, attested, logged artifacts |

One evidence base feeds every column. A control assessed once can satisfy a GxP requirement and a DORA requirement at the same time, which is why the cross-sector profiles share the same engine.
