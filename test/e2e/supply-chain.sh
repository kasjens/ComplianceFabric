#!/usr/bin/env bash
#
# Phase 2 end-to-end proof: trusted delivery, locally reproducible.
#
# Builds a real supply chain with cosign and syft, enforces signature
# verification at admission on a live cluster, and turns a verified SLSA
# provenance attestation into control evidence. It proves, from scratch:
#   1. SBOM     - syft produces an SBOM for the image.
#   2. ATTEST   - cosign attaches the SBOM and a SLSA provenance attestation.
#   3. SIGN     - cosign signs the image.
#   4. DENY     - Kyverno rejects an unsigned image at admission.
#   5. ADMIT    - Kyverno admits the signed image.
#   6. EVIDENCE - cosign verify-attestation -> fabric provenance -> satisfied
#                 evidence the ledger accepts and verifies.
#
# This uses cosign KEY-BASED signing so it runs locally with no OIDC provider.
# The production policy (policies/kyverno/verify-image-signatures.yaml) is
# keyless (Fulcio/Rekor against the CI OIDC identity); its admit path is proven
# in CI, not here. This harness proves the same verifyImages mechanism with a
# local key so the whole chain is reproducible on a developer machine.
#
# cosign is PINNED to v2 and downloaded into a temp dir. This is deliberate:
# cosign v3 defaults to the new Sigstore bundle signature format
# (application/vnd.dev.sigstore.bundle.v0.3+json), which the cosign library
# bundled in Kyverno v1.11.5 cannot read, so v3-signed images fail admission
# with "no matching signatures". cosign v2's default legacy "simplesigning"
# layer is exactly what this Kyverno reads. Pinning keeps the harness
# reproducible regardless of which cosign is on PATH.
#
# Requires: syft, docker, kind, kubectl, go, python3, curl, and outbound
# network access to ttl.sh (an anonymous, ephemeral OCI registry) and to the
# public Sigstore Rekor (signatures upload a transparency-log entry that
# Kyverno verifies). Images and their signatures are pushed to ttl.sh so the
# kind cluster can pull them over the internet; cosign signatures are separate
# OCI objects that `kind load` would not carry, which is why a real registry is
# used.
#
# Env:
#   CLUSTER       kind cluster name           (default: fabric-sc-e2e)
#   KYVERNO_VER   Kyverno release to install  (default: v1.11.5)
#   COSIGN_VER    pinned cosign release       (default: v2.2.4)
#   BASE_IMAGE    image to retag and sign     (default: registry.k8s.io/pause:3.9)
#   BUILDER_ID    trusted builder identity    (default: https://compliancefabric.dev/builders/local)
#   CONTROL_ID    control to key evidence to  (default: cfr-part-11-10a-system-validation)
#   KEEP_CLUSTER  set to 1 to skip teardown   (default: unset -> cluster deleted)

set -euo pipefail

CLUSTER="${CLUSTER:-fabric-sc-e2e}"
KYVERNO_VER="${KYVERNO_VER:-v1.11.5}"
COSIGN_VER="${COSIGN_VER:-v2.2.4}"
BASE_IMAGE="${BASE_IMAGE:-registry.k8s.io/pause:3.9}"
BUILDER_ID="${BUILDER_ID:-https://compliancefabric.dev/builders/local}"
CONTROL_ID="${CONTROL_ID:-cfr-part-11-10a-system-validation}"
NS=sc-e2e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
FABRIC="$WORK/fabric"
COSIGN="$WORK/cosign"

# cosign key-based signing is non-interactive with an empty password.
export COSIGN_PASSWORD=""
export COSIGN_YES="true"

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Kyverno registers its policy webhooks a moment after the deployment reports
# Ready, so the first policy apply can race the webhook coming up ("connection
# refused" calling the webhook); retry to absorb that.
retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    [ "$n" -ge 12 ] && return 1
    sleep 5
  done
}

need() { command -v "$1" >/dev/null 2>&1 || fail "required tool not found: $1"; }
for t in syft docker kind kubectl go python3 curl; do need "$t"; done

cleanup() {
  if [ "${KEEP_CLUSTER:-}" = "1" ]; then
    log "KEEP_CLUSTER=1, leaving cluster $CLUSTER running"
  else
    log "tearing down kind cluster $CLUSTER"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

log "building fabric binary (stdlib-only)"
( cd "$REPO_ROOT" && go build -o "$FABRIC" ./cmd/fabric )

log "fetching pinned cosign $COSIGN_VER (legacy signature format for Kyverno $KYVERNO_VER)"
curl -sSLf -o "$COSIGN" \
  "https://github.com/sigstore/cosign/releases/download/$COSIGN_VER/cosign-linux-amd64"
chmod +x "$COSIGN"

log "generating a local cosign key pair"
( cd "$WORK" && "$COSIGN" generate-key-pair >/dev/null )
KEY="$WORK/cosign.key"
PUB="$WORK/cosign.pub"

# ---------------------------------------------------------------------------
log "building and pushing two images to ttl.sh (signed and unsigned)"
# ---------------------------------------------------------------------------
docker pull "$BASE_IMAGE" >/dev/null
TAG="$(cat /proc/sys/kernel/random/uuid)"
SIGNED_REPO="ttl.sh/cf-signed-$TAG"
UNSIGNED_REPO="ttl.sh/cf-unsigned-$TAG"

docker tag "$BASE_IMAGE" "$SIGNED_REPO:1h"
docker tag "$BASE_IMAGE" "$UNSIGNED_REPO:1h"

# Capture the digest from the push output so the reference is immutable and
# matches exactly what cosign signs and what Kyverno verifies.
SIGNED_DIGEST="$(docker push "$SIGNED_REPO:1h" | grep -oE 'sha256:[a-f0-9]{64}' | head -1)"
UNSIGNED_DIGEST="$(docker push "$UNSIGNED_REPO:1h" | grep -oE 'sha256:[a-f0-9]{64}' | head -1)"
[ -n "$SIGNED_DIGEST" ]   || fail "could not determine signed image digest"
[ -n "$UNSIGNED_DIGEST" ] || fail "could not determine unsigned image digest"
SIGNED_REF="$SIGNED_REPO@$SIGNED_DIGEST"
UNSIGNED_REF="$UNSIGNED_REPO@$UNSIGNED_DIGEST"
echo "signed:   $SIGNED_REF"
echo "unsigned: $UNSIGNED_REF"

# ---------------------------------------------------------------------------
log "1. SBOM: syft generates an SBOM for the signed image"
# ---------------------------------------------------------------------------
SBOM="$WORK/sbom.json"
syft -q "$SIGNED_REF" -o spdx-json > "$SBOM"
[ -s "$SBOM" ] || fail "syft produced an empty SBOM"
echo "PASS: SBOM generated ($(wc -c < "$SBOM") bytes)"

# ---------------------------------------------------------------------------
log "2. ATTEST: cosign attaches the SBOM and a SLSA provenance attestation"
# ---------------------------------------------------------------------------
PROV="$WORK/prov.json"
cat > "$PROV" <<JSON
{"buildDefinition":{"buildType":"https://compliancefabric.dev/local-build/v1","externalParameters":{},"internalParameters":{},"resolvedDependencies":[]},
 "runDetails":{"builder":{"id":"$BUILDER_ID"},"metadata":{"invocationId":"local-1","startedOn":"2026-06-06T10:00:00Z","finishedOn":"2026-06-06T10:05:00Z"}}}
JSON
"$COSIGN" attest --key "$KEY" --type spdxjson       --predicate "$SBOM" "$SIGNED_REF" >/dev/null
"$COSIGN" attest --key "$KEY" --type slsaprovenance1 --predicate "$PROV" "$SIGNED_REF" >/dev/null
echo "PASS: SBOM and SLSA provenance attestations attached"

# ---------------------------------------------------------------------------
log "3. SIGN: cosign signs the image"
# ---------------------------------------------------------------------------
"$COSIGN" sign --key "$KEY" "$SIGNED_REF" >/dev/null
echo "PASS: image signed"

# ---------------------------------------------------------------------------
log "creating kind cluster $CLUSTER and installing Kyverno $KYVERNO_VER"
# ---------------------------------------------------------------------------
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kubectl config use-context "kind-$CLUSTER"
# Server-side apply: the Kyverno CRDs exceed the client-side annotation size limit.
kubectl apply --server-side --force-conflicts \
  -f "https://github.com/kyverno/kyverno/releases/download/$KYVERNO_VER/install.yaml"
kubectl -n kyverno rollout status deployment/kyverno-admission-controller --timeout=180s
kubectl -n kyverno wait --for=condition=Available deployment --all --timeout=180s

log "applying a key-based verifyImages policy"
PUBKEY="$(cat "$PUB")"
POLICY="$WORK/policy.yaml"
{
  cat <<'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures-keyed
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-signed
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "ttl.sh/*"
          required: true
          mutateDigest: false
          attestors:
            - count: 1
              entries:
                - keys:
                    publicKeys: |-
YAML
  printf '%s\n' "$PUBKEY" | sed 's/^/                      /'
} > "$POLICY"
retry kubectl apply -f "$POLICY" \
  || fail "could not apply the verifyImages policy (Kyverno webhook never became ready)"
kubectl wait --for=condition=Ready clusterpolicy/verify-image-signatures-keyed --timeout=90s

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# ---------------------------------------------------------------------------
log "4. DENY: an unsigned image must be rejected at admission"
# ---------------------------------------------------------------------------
set +e
deny_out="$(kubectl -n "$NS" run unsigned --image="$UNSIGNED_REF" --restart=Never 2>&1)"
deny_rc=$?
set -e
echo "$deny_out"
[ "$deny_rc" -ne 0 ] || fail "unsigned image was admitted (expected admission denial)"
echo "$deny_out" | grep -qi 'no matching signatures' \
  || fail "denial did not cite a missing signature"
echo "PASS: unsigned image denied at admission"

# ---------------------------------------------------------------------------
log "5. ADMIT: the signed image must be accepted"
# ---------------------------------------------------------------------------
kubectl -n "$NS" run signed --image="$SIGNED_REF" --restart=Never \
  || fail "signed image was denied (expected admission)"
echo "PASS: signed image admitted"

# ---------------------------------------------------------------------------
log "6. EVIDENCE: verify-attestation -> fabric provenance -> ledger"
# ---------------------------------------------------------------------------
STATEMENT="$WORK/statement.json"
# verify-attestation emits a DSSE envelope; its base64 payload is the in-toto
# statement that `fabric provenance` consumes.
"$COSIGN" verify-attestation --key "$PUB" --type slsaprovenance1 "$SIGNED_REF" \
  | python3 -c 'import sys,json,base64; env=json.loads(sys.stdin.readline()); sys.stdout.write(base64.b64decode(env["payload"]).decode())' \
  > "$STATEMENT"
[ -s "$STATEMENT" ] || fail "could not decode the verified provenance statement"

ledger="$WORK/sc.ledger"
"$FABRIC" provenance "$STATEMENT" "$BUILDER_ID" "$CONTROL_ID" --ledger "$ledger" \
  || fail "fabric provenance exited non-zero on a trusted-builder attestation"
"$FABRIC" ledger verify "$ledger" \
  || fail "ledger chain verification failed"
"$FABRIC" ledger posture "$ledger" \
  || fail "posture reports an open gap for a satisfied artifact"
echo "PASS: provenance evidence collected, ledger intact, posture clean"

log "Phase 2 supply-chain e2e: all assertions passed"
