# Overview

The Compliance Fabric is a control and evidence layer that runs across a regulated Kubernetes platform. It keeps a system continuously demonstrable against its regulatory controls, rather than letting compliance drift between periodic audits.

## The problem

In a GxP environment, running Kubernetes is not the hard part. Proving the system is compliant is. Today that proof is manual and retrospective:

- Validation documents are written after a change, not produced by it.
- Evidence is collected by hand: screenshots, exported configs, approval emails.
- The validated state lives in a spreadsheet that diverges from reality.
- Every change risks invalidating the qualification.

Adding AI agents makes this worse. An agent is a non-deterministic component that the auditor has not seen before, and its behavior is harder to bound and record than a fixed application.

## The concept

The Fabric inverts the model. Controls are written once as code. The platform compiles them into enforced policy, and the running system emits evidence as a byproduct of operating. The same evidence base maps to several regulatory frameworks, so one platform serves pharma (GxP) and finance (DORA, NIS2) without separate tooling.

The design is a closed loop:

1. Authoring: controls expressed in OSCAL, versioned in Git.
2. Enforcement: controls compiled to policy and enforced at CI, admission, and runtime.
3. Operation: regulated workloads and governed agents run on a qualified platform.
4. Assessment: state and telemetry collected and scored against the controls.
5. Reporting: audit packs generated on demand. Gaps feed back to authoring.

## Scope

In scope: platform-level controls, supply-chain integrity, change control, agent governance, evidence collection, and reporting for container-based regulated workloads.

Out of scope: the business validation of a specific application's intended use, the quality decision to release, and the human critical thinking that GAMP 5 and CSA require. The Fabric supports those activities with evidence. It does not perform them.

## Glossary

- GxP: the set of Good Practice regulations (GMP, GLP, GCP, GDP) for life sciences.
- GAMP 5: ISPE guidance for computerized system validation, Second Edition (2022).
- CSA: Computer Software Assurance, the FDA's risk-based validation approach (final guidance, September 2025).
- Annex 11: EU GMP rules for computerized systems. A revision and a new Annex 22 on AI are expected to finalize by mid-2026.
- 21 CFR Part 11: FDA rules for electronic records and electronic signatures.
- ALCOA+: data integrity principles (attributable, legible, contemporaneous, original, accurate, plus complete, consistent, enduring, available).
- OSCAL: the NIST Open Security Controls Assessment Language, a machine-readable format for controls and assessment results.
- SBOM: Software Bill of Materials.
- SLSA: Supply-chain Levels for Software Artifacts, a build-integrity framework.
- DORA: the EU Digital Operational Resilience Act for financial entities.
- NIS2: the EU directive on network and information security.
- ISO 42001: the AI management system standard (2023).
