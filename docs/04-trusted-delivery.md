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

**Implementation status:** `fabric provenance <provenance-json-file> <expected-builder-id> <control-id>` is an evidence producer for the SLSA provenance attestation. It reads an in-toto v1 provenance statement — the decoded payload from `cosign verify-attestation --type slsaprovenance --output json` — and records, per attested artifact, whether the statement is a SLSA provenance attestation built by the expected trusted builder (satisfied) or not (not-satisfied, so an artifact built outside the trusted pipeline is detectable). Records key to the `cfr-part-11-10a-system-validation` control — implemented for this mechanism by a non-Kyverno `supply-chain` component alongside the Kyverno `verify-image-signatures` admission check — and feed the same ledger, `--ledger <path>` to append.

`fabric sbom <sbom-json-file> <policy-file> <control-id>` is the content counterpart to the provenance producer: provenance attests *how* the image was built, the SBOM attests *what is inside it*. It reads a CycloneDX SBOM (as `syft <image> -o cyclonedx-json` emits) and judges the image's component inventory against a banned-components policy. An SBOM that inventories nothing is not evidence of the image's contents (not-satisfied); otherwise every component the policy bans, by exact name and version or by name at any version, yields a not-satisfied record naming that component, and a clean, non-empty inventory yields one satisfied record for the image. It keys to the same `cfr-part-11-10a-system-validation` control through a second `sbom-content` rule on the `supply-chain` component, and feeds the same ledger, `--ledger <path>` to append.

The generation and admission steps are proven by two end-to-end harnesses. `test/e2e/supply-chain.sh` runs the whole chain locally and reproducibly with a key-based cosign: it generates an SBOM with syft, attaches the SBOM and a SLSA provenance attestation and signs the image with cosign, then on a live kind cluster running Kyverno asserts that an unsigned image is denied at admission and the signed image is admitted, and finally turns the verified provenance attestation back into satisfied evidence through this producer. `test/e2e/keyless-ci.sh` (the `keyless-e2e` CI job, `id-token: write`) covers the one strand that cannot run locally: it signs a test image with the GitHub Actions OIDC identity and asserts the same deny/admit behaviour against the production `verify-image-signatures.yaml` policy verbatim. Both kind-based e2e jobs pass in CI. Cosign is pinned to v2 in both harnesses because cosign v3's default new-bundle signature format is unreadable by the cosign library in Kyverno v1.11.5. The dedicated SBOM-content evidence producer described above (`fabric sbom`) now complements the provenance producer. Still to come: binding the generation harness into the release pipeline itself, and feeding the generated SBOM through `fabric sbom` there rather than only as an e2e fixture.

## Change control through GitOps

Git is the desired state of the platform. Argo CD or Flux reconciles the cluster to match it. Two compliance properties fall out of this directly:

- Every change is a pull request. The PR record, with its reviewer approvals and merge timestamp, is the change-control record that Annex 11 and Part 11 expect. A reviewed, approved, merged PR is an electronic record of who authorized a change and when.
- Drift detection is continuous. When live state diverges from Git, the controller flags it. This is the same as asking, continuously, whether the qualified state is still intact.

**Implementation status:** the `fabric evidence` command extracts the change-control record from a pull request (`gh pr view --json` output) — author, reviewer approvals, merge timestamp, and merge commit — and flags records that are not valid authorized changes (not merged, no approval, and so on). Given a control id (`fabric evidence <pr-json-file> annex11-10-change-control`) it emits a machine-readable evidence-ledger record keyed to that control, with the change embedded as raw evidence. It exits non-zero on findings so it can gate CI. The `annex11-10-change-control` control is implemented by a non-Kyverno `gitops` component, so coverage and assessment recognise it as enforced. With `--ledger <path>` the record is appended to the append-only, tamper-evident evidence ledger, and `fabric ledger assess` normalizes the stored records into an OSCAL assessment-results document (see `07-evidence-and-audit.md`). Drift detection is implemented as a second producer: `fabric drift` reads Argo CD application sync status (`kubectl get applications -o json`) and emits evidence keyed to `annex11-11-periodic-evaluation` — a Synced application evidences that the running state still matches the validated state in Git, while OutOfSync is drift from the qualified state.

## Mapping to electronic records

A merge that changes the platform is an attributable, time-stamped, retained record of an authorized change. Paired with the transparency log entry for the artifact it deploys, it links a specific change to a specific, verified build. That chain is the evidence a Part 11 or Annex 11 reviewer asks for.
