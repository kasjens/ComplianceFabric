# ADR 0002: Kyverno as the primary policy engine

## Status

Accepted (reference design).

## Context

Enforcement needs admission control, runtime checks, and image signature verification. Two engines are common: Kyverno and OPA / Gatekeeper. Choosing a primary keeps the policy surface consistent without losing expressiveness for hard cases.

## Decision

Use Kyverno as the primary engine. Policies are Kubernetes resources, so they stay inside the same Git and GitOps flow as everything else, and Kyverno verifies image signatures and attestations natively. Use OPA / Gatekeeper for policies that need Rego's expressiveness, such as cross-resource logic. Compliance-to-Policy generates for both, so the engine choice stays behind the control.

## Consequences

- Most policy stays declarative and reviewable as Kubernetes resources.
- Image verification is handled by the same engine that handles admission, reducing moving parts.
- Two engines run, which is more to operate than one. The benefit is matching the engine to the policy rather than forcing all logic into one.
