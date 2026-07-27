#!/usr/bin/env bash
#
# End-to-end proof that every CLI subcommand actually runs.
#
# Eight commands were covered by `go test` but never executed as the real binary
# in CI: report, drift, eval-gate, ledger assess, registry validate, collect,
# crosswalk, and serve. A unit test proves a function; it does not prove the
# command wired to it parses its flags, finds its inputs, and exits with the code
# the pipeline branches on. This harness runs each of them against committed
# control data and generated fixtures, and asserts the output.
#
# Crosswalk gets particular attention: it is the headline capability of the
# cross-sector phase and, until now, ran only under `go test`. Here every anchor
# control named by every committed crosswalk is given real satisfied evidence,
# then each crosswalk is applied to that ledger and its derived citations are
# required to come out satisfied and to verify as a chain.
#
# Requires: go, curl. No external Go modules (fabric is stdlib-only) and no jq.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
FABRIC="$WORK/fabric"
LEDGER="$WORK/evidence.jsonl"

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -n "${SERVE_PID:-}" ]; then kill "$SERVE_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$REPO_ROOT"

log "building fabric binary (stdlib-only)"
go build -o "$FABRIC" ./cmd/fabric

# ---------------------------------------------------------------- report ----
log "fabric report"
"$FABRIC" report controls > "$WORK/report.txt" || fail "report exited non-zero"
[ -s "$WORK/report.txt" ] || fail "report produced no output"

# ------------------------------------------------------- registry validate ----
log "fabric registry validate"
"$FABRIC" registry validate registry || fail "registry validate exited non-zero"

# ----------------------------------------------------------------- drift ----
# Every anchor control referenced by every committed crosswalk. Array elements
# sit alone on a line; "control": "..." pairs carry a colon, so this selects
# anchors only.
log "collecting crosswalk anchor controls"
ANCHORS="$(sed -n 's/^[[:space:]]*"\([a-z0-9._-]*\)",\{0,1\}$/\1/p' controls/crosswalks/*.json | sort -u)"
[ -n "$ANCHORS" ] || fail "no anchor controls found in controls/crosswalks"
printf '%s\n' "$ANCHORS" | sed 's/^/  anchor: /'

cat > "$WORK/apps-synced.json" <<'JSON'
{"items":[{"metadata":{"name":"payments"},
           "status":{"sync":{"status":"Synced"},"reconciledAt":"2026-07-01T10:00:00Z"}}]}
JSON

log "fabric drift (one satisfied record per anchor control)"
for control in $ANCHORS; do
  "$FABRIC" drift "$WORK/apps-synced.json" "$control" --ledger "$LEDGER" >/dev/null \
    || fail "drift exited non-zero for $control"
done

# ------------------------------------------------------------- eval-gate ----
cat > "$WORK/eval-run.json" <<'JSON'
{"agent":"release-reviewer","version":"1.2.0","run-at":"2026-07-01T10:00:00Z",
 "results":[{"case":"refuses-unqualified-tool","suite":"safety","passed":true},
            {"case":"cites-evidence","suite":"accuracy","passed":true}]}
JSON
cat > "$WORK/eval-gate.json" <<'JSON'
{"required-suites":["safety","accuracy"],"max-failures":0}
JSON

log "fabric eval-gate (passing run clears)"
"$FABRIC" eval-gate "$WORK/eval-run.json" "$WORK/eval-gate.json" \
  eu-ai-act-9-risk-management --ledger "$LEDGER" >/dev/null \
  || fail "eval-gate exited non-zero for a passing run"

cat > "$WORK/eval-run-fail.json" <<'JSON'
{"agent":"release-reviewer","version":"1.3.0","run-at":"2026-07-01T11:00:00Z",
 "results":[{"case":"refuses-unqualified-tool","suite":"safety","passed":false}]}
JSON

log "fabric eval-gate (failing run blocks)"
if "$FABRIC" eval-gate "$WORK/eval-run-fail.json" "$WORK/eval-gate.json" \
     eu-ai-act-9-risk-management >/dev/null 2>&1; then
  fail "eval-gate cleared a run with a failed required suite"
fi

# ---------------------------------------------------------------- ledger ----
log "fabric ledger verify/assess/posture"
"$FABRIC" ledger verify  "$LEDGER" >/dev/null || fail "ledger verify exited non-zero"
"$FABRIC" ledger assess  "$LEDGER" > "$WORK/assess.json" || fail "ledger assess exited non-zero"
"$FABRIC" ledger posture "$LEDGER" > "$WORK/posture.txt" || fail "ledger posture exited non-zero"
[ -s "$WORK/assess.json" ]  || fail "ledger assess produced no output"
[ -s "$WORK/posture.txt" ]  || fail "ledger posture produced no output"

# ------------------------------------------------------------- crosswalk ----
# The cross-sector claim, proven against a real ledger rather than a unit
# fixture: each crosswalk's citations must come out satisfied when every anchor
# behind them is satisfied, and the derived ledger must verify.
for cw in controls/crosswalks/*.json; do
  name="$(basename "$cw" .json)"
  derived="$WORK/derived-$name.jsonl"

  log "fabric crosswalk ($name)"
  "$FABRIC" crosswalk "$cw" "$LEDGER" --ledger "$derived" > "$WORK/cw-$name.json" \
    || fail "crosswalk exited non-zero for $name"

  [ -s "$WORK/cw-$name.json" ] || fail "crosswalk $name produced no derived records"
  if grep -q 'not-satisfied' "$WORK/cw-$name.json"; then
    printf '%s\n' "$(cat "$WORK/cw-$name.json")" >&2
    fail "crosswalk $name emitted a not-satisfied citation even though every anchor is satisfied"
  fi
  "$FABRIC" ledger verify "$derived" >/dev/null \
    || fail "derived crosswalk ledger does not verify for $name"
done

# A crosswalk over an EMPTY source ledger must not report its citations
# satisfied. This is the vacuity guard: absence of evidence is not compliance.
log "fabric crosswalk (empty source ledger must not satisfy)"
: > "$WORK/empty.jsonl"
"$FABRIC" crosswalk controls/crosswalks/dora.json "$WORK/empty.jsonl" \
  > "$WORK/cw-empty.json" 2>/dev/null || true
if ! grep -q 'not-satisfied' "$WORK/cw-empty.json"; then
  fail "crosswalk over an empty ledger did not report not-satisfied"
fi

# --------------------------------------------------------------- collect ----
log "fabric collect --once"
cp "$WORK/apps-synced.json" "$WORK/collect-apps.json"
cat > "$WORK/collect.json" <<JSON
{"interval":"30s","sources":[
  {"type":"drift","command":["cat","$WORK/collect-apps.json"],
   "control":"annex11-11-periodic-evaluation"}
]}
JSON
"$FABRIC" collect "$WORK/collect.json" --ledger "$WORK/collected.jsonl" --once \
  || fail "collect --once exited non-zero"
"$FABRIC" ledger verify "$WORK/collected.jsonl" >/dev/null \
  || fail "collected ledger does not verify"

log "fabric collect rejects a non-positive interval"
cat > "$WORK/collect-bad.json" <<JSON
{"interval":"0s","sources":[
  {"type":"drift","command":["cat","$WORK/collect-apps.json"],
   "control":"annex11-11-periodic-evaluation"}
]}
JSON
if "$FABRIC" collect "$WORK/collect-bad.json" --ledger "$WORK/x.jsonl" --once >/dev/null 2>&1; then
  fail "collect accepted a zero interval (this panics NewTicker in the long-running path)"
fi

# ----------------------------------------------------------------- serve ----
log "fabric serve (dashboard, /posture.json, /trend.json)"
ADDR="127.0.0.1:18099"
"$FABRIC" serve "$LEDGER" --addr "$ADDR" >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS "http://$ADDR/posture.json" >/dev/null 2>&1; then break; fi
  sleep 0.2
done

curl -fsS "http://$ADDR/"            > "$WORK/dash.html"    || fail "GET / failed"
curl -fsS "http://$ADDR/posture.json" > "$WORK/posture.json" || fail "GET /posture.json failed"
curl -fsS "http://$ADDR/trend.json"   > "$WORK/trend.json"   || fail "GET /trend.json failed"

grep -q '<html' "$WORK/dash.html" || fail "dashboard did not return HTML"
head -c 1 "$WORK/posture.json" | grep -q '[[{]' || fail "/posture.json is not JSON"
head -c 1 "$WORK/trend.json"   | grep -q '[[{]' || fail "/trend.json is not JSON"

kill "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

printf '\nOK: report, registry validate, drift, eval-gate, ledger verify/assess/posture,\n'
printf 'crosswalk (all committed crosswalks + vacuity guard), collect, and serve all\n'
printf 'ran as the real binary.\n'
