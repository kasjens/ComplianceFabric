# ADR 0003: Sigstore as the supply-chain trust root

## Status

Accepted (reference design).

## Context

Admission must trust only artifacts the platform built and can account for. Traditional signing needs long-lived private keys, which are an operational and security burden in a regulated setting.

## Decision

Use Sigstore for artifact trust. Sign with Cosign using short-lived certificates from Fulcio tied to the build's OIDC identity, and record signatures in Rekor, an append-only transparency log. Pair signatures with SBOMs (Syft) and SLSA provenance. Admission verifies the signing identity and provenance before allowing a workload.

## Consequences

- No long-lived signing keys to store, rotate, or revoke.
- The transparency log gives a tamper-evident record that doubles as evidence, referenced from the evidence ledger.
- Trust is bound to a build identity, not a key, which matches the least-privilege model used elsewhere.
- The build pipeline's OIDC identity becomes a high-value trust boundary and must be protected accordingly.
