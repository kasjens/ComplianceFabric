#!/usr/bin/env bash
#
# Phase 2 keyless admit-path proof. CI-ONLY.
#
# Proves the *production* policy (policies/kyverno/verify-image-signatures.yaml),
# which trusts a Sigstore *keyless* signature chained to this repository's GitHub
# Actions OIDC identity. It signs a test image with the ambient Actions identity
# (no key material), then asserts on a live cluster that:
#   1. DENY  - an unsigned image is rejected at admission.
#   2. ADMIT - the image signed by this workflow's identity is admitted.
#
# This is the one strand of Phase 2 that cannot run locally: keyless signing
# needs an OIDC provider (Fulcio/Rekor against the GitHub Actions token), which
# only exists inside CI. The key-based equivalent runs locally as
# test/e2e/supply-chain.sh.
#
# The workflow that calls this MUST grant `id-token: write` so cosign can mint a
# Fulcio certificate from the Actions OIDC token.
#
# cosign is PINNED to v2: cosign v3 defaults to the new Sigstore bundle format
# that the cosign library in Kyverno v1.11.5 cannot read (see supply-chain.sh).
#
# Requires (all present on GitHub-hosted runners or installed by the workflow):
# cosign-compatible OIDC env, docker, kind, kubectl, go, curl, and outbound
# network to ttl.sh and the public Sigstore (Fulcio + Rekor).
#
# Env:
#   CLUSTER       kind cluster name           (default: fabric-keyless-e2e)
#   KYVERNO_VER   Kyverno release to install  (default: v1.11.5)
#   COSIGN_VER    pinned cosign release       (default: v2.2.4)
#   BASE_IMAGE    image to retag and sign     (default: registry.k8s.io/pause:3.9)
#   KEEP_CLUSTER  set to 1 to skip teardown   (default: unset -> cluster deleted)

set -euo pipefail

CLUSTER="${CLUSTER:-fabric-keyless-e2e}"
KYVERNO_VER="${KYVERNO_VER:-v1.11.5}"
COSIGN_VER="${COSIGN_VER:-v2.2.4}"
BASE_IMAGE="${BASE_IMAGE:-registry.k8s.io/pause:3.9}"
NS=keyless-e2e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
COSIGN="$WORK/cosign"
POLICY="$REPO_ROOT/policies/kyverno/verify-image-signatures.yaml"

# Keyless signing is non-interactive; auto-confirm the Rekor upload prompt.
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
for t in docker kind kubectl curl; do need "$t"; done

# Keyless signing requires the GitHub Actions OIDC token. Refuse to run without
# it rather than fall back to an interactive browser flow that would hang CI.
[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] \
  || fail "no GitHub Actions OIDC token in environment (this script is CI-only; run supply-chain.sh locally)"

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

log "fetching pinned cosign $COSIGN_VER (legacy signature format for Kyverno $KYVERNO_VER)"
curl -sSLf -o "$COSIGN" \
  "https://github.com/sigstore/cosign/releases/download/$COSIGN_VER/cosign-linux-amd64"
chmod +x "$COSIGN"

# ---------------------------------------------------------------------------
log "building and pushing two images to ttl.sh (signed and unsigned)"
# ---------------------------------------------------------------------------
docker pull "$BASE_IMAGE" >/dev/null
TAG="$(cat /proc/sys/kernel/random/uuid)"
SIGNED_REPO="ttl.sh/cf-keyless-signed-$TAG"
UNSIGNED_REPO="ttl.sh/cf-keyless-unsigned-$TAG"
docker tag "$BASE_IMAGE" "$SIGNED_REPO:1h"
docker tag "$BASE_IMAGE" "$UNSIGNED_REPO:1h"
SIGNED_DIGEST="$(docker push "$SIGNED_REPO:1h" | grep -oE 'sha256:[a-f0-9]{64}' | head -1)"
UNSIGNED_DIGEST="$(docker push "$UNSIGNED_REPO:1h" | grep -oE 'sha256:[a-f0-9]{64}' | head -1)"
[ -n "$SIGNED_DIGEST" ]   || fail "could not determine signed image digest"
[ -n "$UNSIGNED_DIGEST" ] || fail "could not determine unsigned image digest"
SIGNED_REF="$SIGNED_REPO@$SIGNED_DIGEST"
UNSIGNED_REF="$UNSIGNED_REPO@$UNSIGNED_DIGEST"
echo "signed:   $SIGNED_REF"
echo "unsigned: $UNSIGNED_REF"

# ---------------------------------------------------------------------------
log "keyless-signing the image with the GitHub Actions OIDC identity"
# ---------------------------------------------------------------------------
# No --key: cosign requests a short-lived Fulcio certificate against the Actions
# OIDC token and records the signature in Rekor. The certificate subject is this
# workflow's identity, which is exactly what the production policy trusts.
"$COSIGN" sign "$SIGNED_REF"
echo "PASS: image keyless-signed"

# ---------------------------------------------------------------------------
log "creating kind cluster $CLUSTER and installing Kyverno $KYVERNO_VER"
# ---------------------------------------------------------------------------
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kubectl config use-context "kind-$CLUSTER"
kubectl apply --server-side --force-conflicts \
  -f "https://github.com/kyverno/kyverno/releases/download/$KYVERNO_VER/install.yaml"
kubectl -n kyverno rollout status deployment/kyverno-admission-controller --timeout=180s
kubectl -n kyverno wait --for=condition=Available deployment --all --timeout=180s

log "applying the production keyless policy verbatim"
retry kubectl apply -f "$POLICY" \
  || fail "could not apply the keyless policy (Kyverno webhook never became ready)"
kubectl wait --for=condition=Ready clusterpolicy/verify-image-signatures --timeout=90s
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# ---------------------------------------------------------------------------
log "1. DENY: an unsigned image must be rejected at admission"
# ---------------------------------------------------------------------------
set +e
deny_out="$(kubectl -n "$NS" run unsigned --image="$UNSIGNED_REF" --restart=Never 2>&1)"
deny_rc=$?
set -e
echo "$deny_out"
[ "$deny_rc" -ne 0 ] || fail "unsigned image was admitted (expected admission denial)"
echo "PASS: unsigned image denied at admission"

# ---------------------------------------------------------------------------
log "2. ADMIT: the keyless-signed image must be accepted"
# ---------------------------------------------------------------------------
kubectl -n "$NS" run signed --image="$SIGNED_REF" --restart=Never \
  || fail "keyless-signed image was denied (expected admission)"
echo "PASS: keyless-signed image admitted"

log "Phase 2 keyless admit-path e2e: all assertions passed"
