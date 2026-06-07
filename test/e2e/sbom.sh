#!/usr/bin/env bash
#
# Phase 2/3 end-to-end proof: SBOM-content evidence from a real syft scan.
#
# The `fabric sbom` producer is unit-tested against a hand-written CycloneDX
# fixture. This harness proves it consumes the genuine article: it runs syft over
# a real container image to produce a CycloneDX SBOM, then asserts both verdicts
# the producer claims, against that real inventory:
#   1. BLOCK - a banned component that is actually present (musl) yields a
#              not-satisfied record and a non-zero exit.
#   2. ADMIT - a policy banning only absent components yields a satisfied record,
#              a zero exit, and ledger evidence whose chain verifies.
#
# This closes the gap between "parses a fixture" and "parses what syft emits".
#
# Requires: go, syft, docker (syft pulls the image if it is not local). No
# external Go modules (the fabric binary is stdlib-only).
#
# Env:
#   IMAGE  image to inventory  (default: alpine:latest)
#   BANNED a package known to be present in IMAGE  (default: musl)

set -euo pipefail

IMAGE="${IMAGE:-alpine:latest}"
BANNED="${BANNED:-musl}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
FABRIC="$WORK/fabric"
SBOM="$WORK/sbom.cyclonedx.json"
CONTROL=cfr-part-11-10a-system-validation

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

log "building fabric binary (stdlib-only)"
( cd "$REPO_ROOT" && go build -o "$FABRIC" ./cmd/fabric )

log "generating a real CycloneDX SBOM for $IMAGE with syft"
syft "$IMAGE" -o cyclonedx-json > "$SBOM" 2>/dev/null
# syft emits compact (single-line) JSON, so count matches, not lines.
count="$(grep -o '"bom-ref"' "$SBOM" | wc -l | tr -d ' ')"
echo "SBOM components (bom-ref entries): $count"
[ "$count" -gt 0 ] || fail "syft produced an empty SBOM"
grep -q "\"$BANNED\"" "$SBOM" || fail "expected component $BANNED not found in $IMAGE SBOM"

# ---------------------------------------------------------------------------
log "1. BLOCK: a banned component that is present ($BANNED) -> not-satisfied"
# ---------------------------------------------------------------------------
cat > "$WORK/ban-present.json" <<JSON
{"banned":[{"name":"$BANNED","version":""}]}
JSON
set +e
"$FABRIC" sbom "$SBOM" "$WORK/ban-present.json" "$CONTROL" > "$WORK/present.json"
rc=$?
set -e
cat "$WORK/present.json"
[ "$rc" -ne 0 ] || fail "fabric sbom exited 0 with a banned component present"
grep -q '"result": "not-satisfied"' "$WORK/present.json" \
  || fail "expected a not-satisfied record for the banned component"
echo "PASS: present banned component produced not-satisfied evidence (exit $rc)"

# ---------------------------------------------------------------------------
log "2. ADMIT: a policy banning only absent components -> satisfied + ledger"
# ---------------------------------------------------------------------------
cat > "$WORK/ban-absent.json" <<'JSON'
{"banned":[
  {"name":"log4j-core","version":""},
  {"name":"openssl","version":"0.0.0-does-not-exist"}
]}
JSON
ledger="$WORK/sbom.ledger"
"$FABRIC" sbom "$SBOM" "$WORK/ban-absent.json" "$CONTROL" --ledger "$ledger" \
  > "$WORK/absent.json" || fail "fabric sbom exited non-zero on a clean inventory"
cat "$WORK/absent.json"
grep -q '"result": "satisfied"' "$WORK/absent.json" \
  || fail "expected a satisfied record for the clean inventory"
"$FABRIC" ledger verify "$ledger" || fail "ledger chain verification failed"
"$FABRIC" ledger posture "$ledger" || fail "posture reports an open gap for a clean SBOM"
echo "PASS: clean inventory produced satisfied evidence; ledger intact, posture clean"

log "SBOM-content e2e: all assertions passed"
