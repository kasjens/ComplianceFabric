# Trusted delivery and change control

This layer answers two audit questions for everything that runs: what is it, and how did it get here. It proves artifact integrity and records every change.

## Supply-chain integrity

Three artifacts are produced for each build and bound to the image digest:

- An SBOM (Software Bill of Materials) listing every component and version. Generated with Syft in CycloneDX or SPDX format.
- An SLSA provenance attestation recording how and where the image was built.
- A signature over both, using Sigstore.

Sigstore signs without long-lived keys. Cosign requests a short-lived certificate from Fulcio against the build's OIDC identity, signs the artifact, and records the signature in Rekor, a public, append-only transparency log. The signing identity, not a stored key, is the thing admission trusts.

```bash
# In the build pipeline
syft registry.example.internal/mes:1.4.2 -o cyclonedx-json > sbom.json
cosign attest --predicate sbom.json --type cyclonedx \
  registry.example.internal/mes:1.4.2
cosign sign registry.example.internal/mes:1.4.2
```

Admission then verifies the signature and provenance before allowing the workload, as shown in `03-policy-enforcement.md`. The rule is simple: no valid signature and provenance, no deploy.

## Change control through GitOps

Git is the desired state of the platform. Argo CD or Flux reconciles the cluster to match it. Two compliance properties fall out of this directly:

- Every change is a pull request. The PR record, with its reviewer approvals and merge timestamp, is the change-control record that Annex 11 and Part 11 expect. A reviewed, approved, merged PR is an electronic record of who authorized a change and when.
- Drift detection is continuous. When live state diverges from Git, the controller flags it. This is the same as asking, continuously, whether the qualified state is still intact.

**Implementation status:** the `fabric evidence` command extracts the change-control record from a pull request (`gh pr view --json` output) — author, reviewer approvals, merge timestamp, and merge commit — and flags records that are not valid authorized changes (not merged, no approval, and so on). Given a control id (`fabric evidence <pr-json-file> annex11-10-change-control`) it emits a machine-readable evidence-ledger record keyed to that control, with the change embedded as raw evidence. It exits non-zero on findings so it can gate CI. The `annex11-10-change-control` control is implemented by a non-Kyverno `gitops` component, so coverage and assessment recognise it as enforced. With `--ledger <path>` the record is appended to the append-only, tamper-evident evidence ledger, and `fabric ledger assess` normalizes the stored records into an OSCAL assessment-results document (see `07-evidence-and-audit.md`). Drift detection is implemented as a second producer: `fabric drift` reads Argo CD application sync status (`kubectl get applications -o json`) and emits evidence keyed to `annex11-11-periodic-evaluation` — a Synced application evidences that the running state still matches the validated state in Git, while OutOfSync is drift from the qualified state.

## Mapping to electronic records

A merge that changes the platform is an attributable, time-stamped, retained record of an authorized change. Paired with the transparency log entry for the artifact it deploys, it links a specific change to a specific, verified build. That chain is the evidence a Part 11 or Annex 11 reviewer asks for.
