# Policy translation and enforcement

Authored controls are useless until they run. This layer compiles OSCAL controls into Kubernetes policy and enforces them at three points: in CI, at admission, and at runtime.

## Compliance-to-Policy

Compliance-to-Policy (C2P), part of the OSCAL Compass project, bridges controls and policy. It reads an OSCAL component definition, generates policy in the native format of each engine, and collects the engines' results back into OSCAL assessment results. It runs as a Kubernetes controller or as a step in a GitOps pipeline.

C2P is the hinge of the whole design. It is the reason an auditor can trace a deployed policy back to the control it implements, and trace an assessment result forward to the control it satisfies.

## Policy engines

Two engines cover the range of needs:

- Kyverno for the majority of policies. Policies are Kubernetes resources, which keeps them inside the same review and GitOps flow as everything else. Kyverno also verifies image signatures and attestations directly.
- OPA / Gatekeeper for policies that need the expressiveness of Rego, such as cross-resource logic.

C2P generates for both, so the choice of engine is an implementation detail behind the control.

## Enforcement points

- CI (shift left): policy checks run against manifests before merge, so violations are caught without a cluster.
- Admission (the gate): the admission controller rejects non-compliant resources at deploy time. This is where unsigned images and policy violations are blocked.
- Runtime (continuous): policies are re-evaluated against live cluster state, so drift and out-of-band changes are detected, not just deploy-time violations.

## Example: require a signed, attested image

A Kyverno policy that blocks any image without a valid signature from the trusted build identity:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
  annotations:
    fabric.control-id: cfr-part-11-system-access-control
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences: ["registry.example.internal/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://ci.example.internal/build"
                    issuer: "https://token.actions.example.internal"
```

The `fabric.control-id` annotation is what lets the evidence layer attribute every allow or deny back to a control.

## Output

Every enforcement decision is an assessment data point. C2P normalizes engine results into OSCAL assessment results, which the evidence layer stores and the reporting layer renders.
