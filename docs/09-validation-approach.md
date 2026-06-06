# Validation approach

The Fabric is designed to fit the risk-based assurance model in GAMP 5 Second Edition and the FDA Computer Software Assurance (CSA) guidance finalized in September 2025, and to support the EU GMP Annex 11 and Annex 22 revisions expected to finalize by mid-2026. It supports validation. It does not perform it.

## Separate platform qualification from workload validation

The central pattern is separation of concerns. Qualify the platform once, then validate each workload against its intended use on top of a known-good foundation. This is a proven approach in regulated cloud projects, and it is what keeps validation effort proportional rather than repeated.

- Platform qualification covers the cluster baseline, the installed controllers, and the policies in force. The Fabric defines this baseline as code and detects drift from it continuously.
- Workload validation covers a specific application's intended use. The platform team does not re-qualify Kubernetes for each application; they validate the application against the qualified baseline.

## Computer Software Assurance fit

CSA favors critical thinking and risk-based assurance over exhaustive scripted testing, and it allows supplier evidence and automated evidence generation. The Fabric supports this directly:

- It generates evidence automatically as a byproduct of operating, which is the kind of assurance CSA encourages over brute-force retesting.
- It scopes effort by control criticality through OSCAL profiles, which matches the risk-based principle.
- It produces IQ/OQ/PQ evidence from collected records rather than from manual test execution where the control allows it.

## What the Fabric does not do

- It does not make the validation decision or the release decision. A qualified person does.
- It does not replace the critical thinking GAMP 5 and CSA require. It gives that thinking better inputs.
- It does not certify compliance. There is no GxP certification body. The Fabric produces evidence; the organization and its auditors judge it.

Stating this boundary plainly is a feature. It matches how regulators expect assurance to work and it sets honest expectations with a quality team.
