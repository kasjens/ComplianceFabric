# Policy translation and enforcement

Authored controls are useless until they run. This layer compiles OSCAL controls into Kubernetes policy and enforces them at three points: in CI, at admission, and at runtime.

## Compliance-to-Policy

Compliance-to-Policy (C2P), part of the OSCAL Compass project, bridges controls and policy. It reads an OSCAL component definition, generates policy in the native format of each engine, and collects the engines' results back into OSCAL assessment results. It runs as a Kubernetes controller or as a step in a GitOps pipeline.

C2P is the hinge of the whole design. It is the reason an auditor can trace a deployed policy back to the control it implements, and trace an assessment result forward to the control it satisfies.

**Implementation status:** C2P is not yet wired in. Today an interim native composer (`fabric generate`) reads the profile and component definitions and composes the deployable Kyverno policy set for the selected controls. The component definitions already follow the OSCAL rule_set convention C2P expects, so the composer is swappable for C2P without changing the control data. The composer only *composes* existing policies; it does not author them.

## Policy engines

Two engines cover the range of needs:

- Kyverno for the majority of policies. Policies are Kubernetes resources, which keeps them inside the same review and GitOps flow as everything else. Kyverno also verifies image signatures and attestations directly.
- OPA / Gatekeeper for policies that need the expressiveness of Rego, such as cross-resource logic.

C2P generates for both, so the choice of engine is an implementation detail behind the control.

## Enforcement points

- CI (shift left): policy checks run against manifests before merge, so violations are caught without a cluster.
- Admission (the gate): the admission controller rejects non-compliant resources at deploy time. This is where unsigned images and policy violations are blocked.
- Runtime (continuous): policies are re-evaluated against live cluster state, so drift and out-of-band changes are detected, not just deploy-time violations.

**Implementation status:** admission and runtime enforcement are proven on a live cluster by a committed, reproducible harness ([`test/e2e/admission.sh`](../test/e2e/admission.sh)), run as a kind-based CI job. It stands up Kyverno, applies the Phase 1 policy library (the image-signature policy excepted — that is Phase 2 and needs Sigstore), and asserts all three: a non-compliant Pod is denied at admission, a compliant Pod is admitted, and Kyverno's background scan produces a PolicyReport that `fabric policy-report` turns into satisfied evidence the ledger accepts and verifies. CI enforcement of manifests before merge is the one enforcement point still to wire.

## Example: require a signed image

The shipped `verify-image-signatures` policy ([`policies/kyverno/verify-image-signatures.yaml`](../policies/kyverno/verify-image-signatures.yaml)) blocks any image whose Sigstore keyless signature does not chain to the project's trusted CI identity:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
  annotations:
    fabric.control-id: cfr-part-11-10a-system-validation
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-signed-images
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences: ["*"]
          required: true
          mutateDigest: true
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/kasjens/ComplianceFabric/.github/workflows/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

Adopters replace the subject and issuer with their own signing identity. The `fabric.control-id` annotation is what lets the evidence layer attribute every allow or deny back to a control.

## Output

Every enforcement decision is an assessment data point. C2P normalizes engine results into OSCAL assessment results, which the evidence layer stores and the reporting layer renders.
