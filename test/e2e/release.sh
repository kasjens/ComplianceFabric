#!/usr/bin/env bash
#
# Phase 2/3 end-to-end proof: the release evidence gate, binding the generation
# harness into the release pipeline.
#
# `fabric release-gate` is unit-tested in internal/release against fixtures. This
# harness proves it gates a *real* release: it generates a genuine CycloneDX SBOM
# with syft (the same generation step the release pipeline runs), pairs it with a
# SLSA provenance attestation, and runs both through one release manifest, asserting
# the two verdicts the gate claims:
#   1. CLEAR - a clean SBOM (bans only absent components) plus provenance from the
#              trusted builder clears the gate (exit 0): all evidence is appended to
#              a fresh per-release ledger, the chain verifies, and posture is clean.
#              The verified ledger is the release evidence artifact.
#   2. BLOCK - a banned component that is actually present in the image blocks the
#              release (exit 1), so a bad build does not ship.
#   3. BLOCK - provenance from an untrusted builder blocks the release (exit 1), so
#              an artifact built outside the trusted pipeline does not ship.
#
# This is what "binding the generation harness into the release pipeline rather than
# as an e2e proof" means: the same syft SBOM and provenance attestation a release
# produces become the gate's input and the release's evidence ledger.
#
# Requires: go, syft (syft pulls the image if it is not local). No external Go
# modules (the fabric binary is stdlib-only).
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
PROVENANCE="$WORK/provenance.json"
CONTROL=cfr-part-11-10a-system-validation
BUILDER="https://github.com/kasjens/ComplianceFabric/.github/workflows/release.yml@refs/heads/main"

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

log "building fabric binary (stdlib-only)"
( cd "$REPO_ROOT" && go build -o "$FABRIC" ./cmd/fabric )

log "generating a real CycloneDX SBOM for $IMAGE with syft"
syft "$IMAGE" -o cyclonedx-json > "$SBOM" 2>/dev/null
count="$(grep -o '"bom-ref"' "$SBOM" | wc -l | tr -d ' ')"
echo "SBOM components (bom-ref entries): $count"
[ "$count" -gt 0 ] || fail "syft produced an empty SBOM"
grep -q "\"$BANNED\"" "$SBOM" || fail "expected component $BANNED not found in $IMAGE SBOM"

# A SLSA v1.0 provenance attestation from the trusted release workflow, the decoded
# payload `cosign verify-attestation --type slsaprovenance --output json` emits.
# test/e2e/supply-chain.sh proves the cosign-attest generation of this; here it is a
# fixture so the gate's multi-artifact roll-up can run without cosign.
cat > "$PROVENANCE" <<JSON
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [ { "name": "registry.example/mes", "digest": { "sha256": "1f2e3d4c5b6a7980" } } ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": { "buildType": "https://actions.github.io/buildtypes/workflow/v1" },
    "runDetails": {
      "builder": { "id": "$BUILDER" },
      "metadata": { "finishedOn": "2026-06-07T10:05:00Z" }
    }
  }
}
JSON

# manifest CLEAN BUILDER -> writes a release manifest with the clean SBOM policy and
# the given provenance builder. The release ledger path is the second argument.
write_manifest() {
  local sbom_policy="$1" prov_builder="$2"
  cat > "$WORK/release.json" <<JSON
{
  "release": "mes-1.4.2",
  "sources": [
    {"type":"sbom","file":"$SBOM","control":"$CONTROL","sbom-policy-file":"$sbom_policy"},
    {"type":"provenance","file":"$PROVENANCE","control":"$CONTROL","expected-builder":"$prov_builder"}
  ]
}
JSON
}

cat > "$WORK/ban-absent.json" <<'JSON'
{"banned":[
  {"name":"log4j-core","version":""},
  {"name":"openssl","version":"0.0.0-does-not-exist"}
]}
JSON
cat > "$WORK/ban-present.json" <<JSON
{"banned":[{"name":"$BANNED","version":""}]}
JSON

# ---------------------------------------------------------------------------
log "1. CLEAR: clean SBOM + trusted-builder provenance -> release cleared (exit 0)"
# ---------------------------------------------------------------------------
write_manifest "$WORK/ban-absent.json" "$BUILDER"
ledger="$WORK/release.ledger"
"$FABRIC" release-gate "$WORK/release.json" --ledger "$ledger" > "$WORK/clear.txt" \
  || fail "expected the clean release to clear, but the gate blocked it"
cat "$WORK/clear.txt"
grep -q 'release cleared' "$WORK/clear.txt" || fail "expected a 'release cleared' message"
"$FABRIC" ledger verify "$ledger" || fail "release ledger chain verification failed"
"$FABRIC" ledger posture "$ledger" || fail "posture reports an open gap for a clean release"
echo "PASS: clean release cleared; the verified ledger is the release evidence artifact"

# ---------------------------------------------------------------------------
log "2. BLOCK: a banned component present in the image -> release blocked (exit 1)"
# ---------------------------------------------------------------------------
write_manifest "$WORK/ban-present.json" "$BUILDER"
set +e
"$FABRIC" release-gate "$WORK/release.json" --ledger "$WORK/blocked1.ledger" > "$WORK/block1.txt"
rc=$?
set -e
cat "$WORK/block1.txt"
[ "$rc" -eq 1 ] || fail "expected exit 1 for a banned component, got $rc"
grep -q 'release blocked' "$WORK/block1.txt" || fail "expected a 'release blocked' message"
echo "PASS: a present banned component blocked the release"

# ---------------------------------------------------------------------------
log "3. BLOCK: provenance from an untrusted builder -> release blocked (exit 1)"
# ---------------------------------------------------------------------------
write_manifest "$WORK/ban-absent.json" "https://evil.example/builder@refs/heads/main"
set +e
"$FABRIC" release-gate "$WORK/release.json" --ledger "$WORK/blocked2.ledger" > "$WORK/block2.txt"
rc=$?
set -e
cat "$WORK/block2.txt"
[ "$rc" -eq 1 ] || fail "expected exit 1 for an untrusted builder, got $rc"
grep -q 'release blocked' "$WORK/block2.txt" || fail "expected a 'release blocked' message"
echo "PASS: an untrusted builder blocked the release"

log "release-gate e2e: all assertions passed"
