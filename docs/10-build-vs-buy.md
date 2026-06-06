# Build versus buy

Most of the Fabric is assembled from mature open source. The product value is in a narrow set of pieces that are hard to build and specific to regulated work. Knowing which is which keeps engineering effort on the parts that are defensible.

## Assemble from open source

These are configured, not built:

- OSCAL and Compliance-to-Policy (OSCAL Compass) for controls as code and policy translation.
- Kyverno and OPA / Gatekeeper for enforcement.
- Syft, SLSA tooling, and Sigstore (Cosign, Fulcio, Rekor) for supply-chain integrity.
- Argo CD or Flux for GitOps change control.
- OpenTelemetry and Open Cluster Management for observability and fleet management.

Building any of these from scratch would be wasted effort. They are reliable, widely used, and standard.

## Build as proprietary IP

These are the product:

- The GxP control library. OSCAL profiles that encode GAMP 5, Annex 11, Part 11, and ALCOA+ into enforceable policy mappings. This is domain work that few people can do well, and it is the hardest part to copy.
- Validation report generation. The logic that assembles IQ/OQ/PQ packs, the Annex 11 audit trail, and the EU AI Act technical file from the evidence ledger.
- Agent governance integration. Wiring the gateway, registry, guardrails, and tracing into the same control and evidence model as the rest of the platform.
- The qualified baseline package. Shipping the platform so it arrives qualifiable, with the baseline, controls, and evidence flow already in place.

## Competitive position

Generic AI-governance platforms map controls to the EU AI Act, NIST AI RMF, and ISO 42001 and produce audit-ready evidence, but they are neither Kubernetes-native nor GxP-specific. GxP work today is sold as project-based validation consulting. The intersection of Kubernetes-native, GxP-specific, and agent-aware is not held by an existing product. That intersection is the position this design takes.
