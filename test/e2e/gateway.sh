#!/usr/bin/env bash
#
# Phase 4 end-to-end proof: the inline agent gateway, live over HTTP.
#
# Runs the real `fabric gateway` HTTP server against the starter registry and a
# content guardrail, then drives it with real requests and asserts the behaviours
# the agent layer claims:
#   1. ADMIT     - a registered agent using its declared model, prompt, and tools
#                  is admitted (HTTP 200, allowed:true).
#   2. BLOCK     - an unregistered agent is blocked at request time (HTTP 403).
#   3. GUARDRAIL - a registered agent whose input carries a sensitive-data
#                  pattern is blocked (HTTP 403), and the interaction log records
#                  the verdict but NEVER the raw input (the input may itself be
#                  the secret the guardrail caught).
#   4. MODEL     - a registered agent asking for an off-list model (one it is not
#                  qualified for) is blocked (HTTP 403).
#   5. OUTPUT    - generated output is screened too: an output carrying a secret
#                  is blocked at /output (HTTP 403) and never written to the log,
#                  while a clean output is admitted (HTTP 200).
#   6. EVIDENCE  - the gateway's own interaction log is consumed verbatim by
#                  `fabric trace`, rolling up as ledger evidence: the admitted
#                  interactions are satisfied, and every blocked interaction
#                  (registration, guardrail, model, and output) is not-satisfied,
#                  so what the gateway enforced inline is faithful in the audit
#                  trail.
#
# This is the proof that the one part of the gateway outside the unit tests - the
# ListenAndServe network shell - actually serves the decision the tests cover.
#
# Requires: go, curl. No cluster, no external Go modules (the fabric binary is
# stdlib-only).
#
# Env:
#   PORT  loopback port for the gateway  (default: 18099)

set -euo pipefail

PORT="${PORT:-18099}"
ADDR="127.0.0.1:$PORT"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
FABRIC="$WORK/fabric"
LOG="$WORK/interactions.log"
GUARDRAIL="$WORK/guardrail.json"
SECRET="AKIAIOSFODNN7EXAMPLE"

GW_PID=""

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# post BODY -> POSTs to the admission endpoint, prints the HTTP code, leaves the
# JSON body in $WORK/body.json.
post() {
  curl -s -o "$WORK/body.json" -w '%{http_code}' -X POST "$ADDR" -d "$1"
}

# post_output BODY -> POSTs to the output-screening endpoint, same outputs.
post_output() {
  curl -s -o "$WORK/body.json" -w '%{http_code}' -X POST "$ADDR/output" -d "$1"
}

log "building fabric binary (stdlib-only)"
( cd "$REPO_ROOT" && go build -o "$FABRIC" ./cmd/fabric )

cat > "$GUARDRAIL" <<'JSON'
{"rules":[
  {"name":"aws-secret-key","pattern":"AKIA[0-9A-Z]{16}"},
  {"name":"private-key-block","pattern":"BEGIN [A-Z ]*PRIVATE KEY"}
]}
JSON

log "starting inline gateway on $ADDR (registry + guardrail + log)"
"$FABRIC" gateway "$REPO_ROOT/registry" \
  --addr "$ADDR" --log "$LOG" --guardrail "$GUARDRAIL" &
GW_PID=$!

# Wait for the listener to accept connections rather than sleeping blindly.
for _ in $(seq 1 50); do
  curl -s -o /dev/null "$ADDR" && break || sleep 0.1
done

# ---------------------------------------------------------------------------
log "1. ADMIT: registered agent, declared model, prompt and tool -> 200 allowed"
# ---------------------------------------------------------------------------
code="$(post '{"id":"i1","agent":"release-reviewer","model":"claude-opus-4","prompt":"change-control-review","tools":["gh-pr-read"],"input":"please review PR 42"}')"
cat "$WORK/body.json"; echo
[ "$code" = "200" ] || fail "expected HTTP 200, got $code"
grep -q '"allowed":true' "$WORK/body.json" || fail "expected allowed:true"
echo "PASS: qualified interaction admitted"

# ---------------------------------------------------------------------------
log "2. BLOCK: unregistered agent -> 403"
# ---------------------------------------------------------------------------
code="$(post '{"id":"i2","agent":"rogue","prompt":"x","tools":[],"input":"hi"}')"
cat "$WORK/body.json"; echo
[ "$code" = "403" ] || fail "expected HTTP 403, got $code"
grep -q 'is not registered' "$WORK/body.json" || fail "expected registration denial reason"
echo "PASS: unregistered agent blocked at request time"

# ---------------------------------------------------------------------------
log "3. GUARDRAIL: registered agent, input carries a secret -> 403, no leak"
# ---------------------------------------------------------------------------
code="$(post "{\"id\":\"i3\",\"agent\":\"release-reviewer\",\"prompt\":\"change-control-review\",\"tools\":[\"gh-pr-read\"],\"input\":\"deploy key $SECRET\"}")"
cat "$WORK/body.json"; echo
[ "$code" = "403" ] || fail "expected HTTP 403, got $code"
grep -q 'guardrail aws-secret-key' "$WORK/body.json" || fail "expected guardrail denial reason"
echo "PASS: sensitive input blocked by guardrail"

# ---------------------------------------------------------------------------
log "4. MODEL: registered agent asks for an off-list model -> 403"
# ---------------------------------------------------------------------------
# The starter release-reviewer agent is qualified for claude-opus-4; a request
# declaring a different model is outside its model allow-list.
code="$(post '{"id":"i4","agent":"release-reviewer","model":"gpt-4o","prompt":"change-control-review","tools":["gh-pr-read"],"input":"please review PR 42"}')"
cat "$WORK/body.json"; echo
[ "$code" = "403" ] || fail "expected HTTP 403, got $code"
grep -q 'not qualified for model gpt-4o' "$WORK/body.json" || fail "expected model denial reason"
echo "PASS: off-list model blocked"

# ---------------------------------------------------------------------------
log "5. OUTPUT: generated output is screened too (secret blocked, clean passes)"
# ---------------------------------------------------------------------------
code="$(post_output "{\"id\":\"o1\",\"agent\":\"release-reviewer\",\"prompt\":\"change-control-review\",\"output\":\"the deploy key is $SECRET\"}")"
cat "$WORK/body.json"; echo
[ "$code" = "403" ] || fail "expected HTTP 403 for secret-bearing output, got $code"
grep -q 'guardrail aws-secret-key' "$WORK/body.json" || fail "expected guardrail denial reason on output"
echo "PASS: sensitive output blocked by guardrail"

code="$(post_output '{"id":"o2","agent":"release-reviewer","prompt":"change-control-review","output":"PR 42 satisfies change control"}')"
cat "$WORK/body.json"; echo
[ "$code" = "200" ] || fail "expected HTTP 200 for clean output, got $code"
grep -q '"allowed":true' "$WORK/body.json" || fail "expected allowed:true for clean output"
echo "PASS: clean output admitted"

# ---------------------------------------------------------------------------
log "6. EVIDENCE: gateway log -> fabric trace -> ledger"
# ---------------------------------------------------------------------------
# Critical safety property: the raw secret must never reach the log, whether it
# arrived as input (i3) or as generated output (o1).
grep -q "$SECRET" "$LOG" && fail "raw guardrail-caught content leaked into the log"
echo "PASS: log records the verdict but never the raw input or output"

echo "--- interaction log ---"
cat "$LOG"

ledger="$WORK/agent.ledger"
records="$WORK/records.json"
# fabric trace exits non-zero because not every interaction is satisfied; that is
# the expected signal here, so do not let set -e abort on it.
set +e
"$FABRIC" trace "$LOG" "$REPO_ROOT/registry" eu-ai-act-12-record-keeping \
  --ledger "$ledger" > "$records"
set -e
echo "--- evidence records ---"
cat "$records"

# Two satisfied (the admitted input i1 and the clean output o2) and four
# not-satisfied (registration block i2, input-guardrail block i3, model block i4,
# output-guardrail block o1). Every block being not-satisfied is the fidelity
# guarantee: a request the gateway blocked on content, model, or registration does
# not roll up as satisfied just because its agent/prompt/tools were registered.
sat="$(grep -c '"result": "satisfied"' "$records" || true)"
notsat="$(grep -c '"result": "not-satisfied"' "$records" || true)"
[ "$sat" = "2" ]    || fail "expected 2 satisfied records, got $sat"
[ "$notsat" = "4" ] || fail "expected 4 not-satisfied records, got $notsat"
echo "PASS: 2 satisfied, 4 not-satisfied (registration + guardrail + model + output blocks all recorded)"

"$FABRIC" ledger verify "$ledger" || fail "ledger chain verification failed"
echo "PASS: ledger chain intact"

log "Phase 4 gateway e2e: all assertions passed"
