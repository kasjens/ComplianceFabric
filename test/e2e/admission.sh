#!/usr/bin/env bash
#
# Phase 1 end-to-end proof: live admission enforcement on a real cluster.
#
# Stands up a kind cluster, installs Kyverno, applies the Phase 1 policy library,
# and asserts the three behaviours Phase 1 claims:
#   1. DENY    - a non-compliant Pod is rejected at admission.
#   2. ADMIT   - a compliant Pod is accepted.
#   3. RUNTIME - Kyverno's background scan emits a PolicyReport for the running
#                workload, and `fabric policy-report` turns it into satisfied
#                evidence that the ledger accepts and verifies.
#
# Requires: kind, kubectl, docker, go. No external Go modules (the fabric binary
# is stdlib-only). cosign is intentionally NOT required: image-signature
# verification is Phase 2 and excluded here.
#
# Env:
#   CLUSTER       kind cluster name           (default: fabric-e2e)
#   KYVERNO_VER   Kyverno release to install  (default: v1.11.5)
#   KEEP_CLUSTER  set to 1 to skip teardown   (default: unset -> cluster deleted)

set -euo pipefail

CLUSTER="${CLUSTER:-fabric-e2e}"
KYVERNO_VER="${KYVERNO_VER:-v1.11.5}"
NS=e2e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
FABRIC="$WORK/fabric"

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Retry a command a few times. Kyverno registers its policy webhooks a moment
# after the deployment reports Ready, so the first policy apply can race the
# webhook endpoint coming up ("connection refused" calling the webhook).
retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    [ "$n" -ge 12 ] && return 1
    sleep 5
  done
}

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

log "creating kind cluster $CLUSTER"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kubectl config use-context "kind-$CLUSTER"

log "installing Kyverno $KYVERNO_VER"
# Server-side apply: the Kyverno CRDs exceed the client-side annotation size limit.
kubectl apply --server-side --force-conflicts \
  -f "https://github.com/kyverno/kyverno/releases/download/$KYVERNO_VER/install.yaml"
kubectl -n kyverno rollout status deployment/kyverno-admission-controller --timeout=180s
kubectl -n kyverno wait --for=condition=Available deployment --all --timeout=180s

log "applying Phase 1 policy library (image-signature policy excluded - Phase 2)"
for p in disallow-cluster-admin-binding require-audit-logging-annotations \
         require-run-as-non-root restrict-anonymous-access; do
  retry kubectl apply -f "$REPO_ROOT/policies/kyverno/$p.yaml" \
    || fail "could not apply policy $p (Kyverno webhook never became ready)"
done
# Wait for the validating policies to report Ready so admission is live.
for p in require-audit-logging-annotations require-run-as-non-root; do
  kubectl wait --for=condition=Ready "clusterpolicy/$p" --timeout=90s
done

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# ---------------------------------------------------------------------------
log "1. DENY: a root Pod with no audit-logging annotation must be rejected"
# ---------------------------------------------------------------------------
set +e
deny_out="$(kubectl -n "$NS" apply -f - 2>&1 <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: violating
spec:
  containers:
    - name: app
      image: registry.k8s.io/pause:3.9
YAML
)"
deny_rc=$?
set -e
echo "$deny_out"
[ "$deny_rc" -ne 0 ] || fail "violating Pod was admitted (expected admission denial)"
echo "$deny_out" | grep -q require-run-as-non-root \
  || fail "denial did not cite require-run-as-non-root"
echo "$deny_out" | grep -q require-audit-logging-annotations \
  || fail "denial did not cite require-audit-logging-annotations"
echo "PASS: non-compliant Pod denied at admission"

# ---------------------------------------------------------------------------
log "2. ADMIT: a compliant Pod must be accepted"
# ---------------------------------------------------------------------------
kubectl -n "$NS" apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: compliant
  annotations:
    gxp.compliancefabric.io/audit-logging: "stdout"
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: app
      image: registry.k8s.io/pause:3.9
      securityContext:
        runAsUser: 65532
YAML
echo "PASS: compliant Pod admitted"

# ---------------------------------------------------------------------------
log "3. RUNTIME: background PolicyReport -> fabric evidence -> ledger"
# ---------------------------------------------------------------------------
# Kyverno's background controller scans the running Pod and writes a PolicyReport.
report="$WORK/policyreport.json"
for i in $(seq 1 30); do
  kubectl get policyreport -n "$NS" -o json > "$report" 2>/dev/null || true
  if grep -q '"result": "pass"' "$report" 2>/dev/null; then
    break
  fi
  sleep 2
done
grep -q '"result": "pass"' "$report" \
  || fail "no passing PolicyReport appeared for the running workload"

ledger="$WORK/runtime.ledger"
"$FABRIC" policy-report "$report" "$REPO_ROOT/policies" --ledger "$ledger" \
  || fail "fabric policy-report exited non-zero on a satisfied report"
"$FABRIC" ledger verify "$ledger" \
  || fail "ledger chain verification failed"
"$FABRIC" ledger posture "$ledger" \
  || fail "posture reports an open gap for a satisfied workload"
echo "PASS: runtime evidence collected, ledger intact, posture clean"

log "Phase 1 e2e: all assertions passed"
