#!/usr/bin/env bash
#
# Phase 4 end-to-end proof: the live LLM/MCP traffic proxy, over HTTP.
#
# Runs the real `fabric gateway-proxy` HTTP server in front of a fake upstream
# "model" endpoint, then drives it with real requests and asserts the behaviours
# the live proxy claims — enforcing the gateway's policy on the actual model call
# on the wire, not on a request a caller declares:
#   1. FORWARD   - a registered agent using its declared model, prompt, and tools
#                  is admitted and its call is forwarded to the upstream; the
#                  agent receives the upstream's response (HTTP 200).
#   2. BLOCK     - an unregistered agent is blocked before the call reaches the
#                  upstream (HTTP 403).
#   3. GUARDRAIL - a registered agent whose request content carries a sensitive
#                  pattern is blocked (HTTP 403), and the call never forwards.
#   4. MODEL     - a registered agent asking for an off-list model (one it is not
#                  qualified for) is blocked (HTTP 403).
#   5. RESPONSE  - the proxy screens the upstream's RESPONSE too: when the model
#                  returns a secret, the proxy blocks it on the way back (HTTP
#                  403) and the secret never reaches the agent; a clean response
#                  passes through unchanged.
#   6. NO LEAK   - the interaction log records every verdict but NEVER the raw
#                  request input or the screened response content.
#   7. EVIDENCE  - the proxy's own interaction log is consumed verbatim by
#                  `fabric trace`, rolling up as ledger evidence: the admitted
#                  request/response phases are satisfied, and every blocked phase
#                  (registration, guardrail, model, and the response block) is
#                  not-satisfied, so what the proxy enforced on live traffic is
#                  faithful in the audit trail.
#
# This is the proof that the one part of the proxy outside the unit tests - the
# ListenAndServe network shell and the real reverse-proxy forwarding - actually
# enforces the decision the tests cover.
#
# Requires: go, curl. No cluster, no external Go modules (both the fabric binary
# and the fake upstream are stdlib-only).
#
# Env:
#   PORT       loopback port for the proxy     (default: 18097)
#   UP_PORT    loopback port for the upstream  (default: 18096)

set -euo pipefail

PORT="${PORT:-18097}"
UP_PORT="${UP_PORT:-18096}"
ADDR="127.0.0.1:$PORT"
UP_ADDR="127.0.0.1:$UP_PORT"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
FABRIC="$WORK/fabric"
LOG="$WORK/interactions.log"
GUARDRAIL="$WORK/guardrail.json"
UPSTREAM_SRC="$WORK/upstream.go"
SECRET="AKIAIOSFODNN7EXAMPLE"
CLEAN_REPLY="PR 42 satisfies change control"

PROXY_PID=""
UP_PID=""

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# post PATH AGENT BODY -> POSTs to the proxy with the given agent identity header,
# prints the HTTP code, leaves the response body in $WORK/body.json. MODEL/PROMPT
# default to the qualified values; override MODEL via the 4th arg.
post() {
  local path="$1" agent="$2" body="$3"
  curl -s -o "$WORK/body.json" -w '%{http_code}' -X POST "$ADDR$path" \
    -H "X-Fabric-Agent: $agent" \
    -H "X-Fabric-Prompt: change-control-review" \
    -d "$body"
}

# A request body the release-reviewer agent is qualified for: its pinned model,
# its declared tool, and a clean user message. $1 overrides the message content;
# $2 overrides the model.
clean_body() {
  local content="${1:-please review PR 42}" model="${2:-claude-opus-4}"
  printf '{"model":"%s","messages":[{"role":"user","content":"%s"}],"tools":[{"type":"function","function":{"name":"gh-pr-read"}}]}' \
    "$model" "$content"
}

log "building fabric binary (stdlib-only)"
( cd "$REPO_ROOT" && go build -o "$FABRIC" ./cmd/fabric )

cat > "$GUARDRAIL" <<'JSON'
{"rules":[
  {"name":"aws-secret-key","pattern":"AKIA[0-9A-Z]{16}"},
  {"name":"private-key-block","pattern":"BEGIN [A-Z ]*PRIVATE KEY"}
]}
JSON

# A fake upstream "model" endpoint: /leak returns a secret-bearing completion (to
# exercise response screening), every other path returns a clean completion. It is
# stdlib-only, so the harness needs no external service.
cat > "$UPSTREAM_SRC" <<GO
package main

import (
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/leak" {
			_, _ = w.Write([]byte("the deploy key is ${SECRET}"))
			return
		}
		_, _ = w.Write([]byte("${CLEAN_REPLY}"))
	})
	_ = http.ListenAndServe(os.Args[1], nil)
}
GO

log "starting fake upstream model endpoint on $UP_ADDR"
( cd "$WORK" && go run "$UPSTREAM_SRC" "$UP_ADDR" ) &
UP_PID=$!
for _ in $(seq 1 100); do
  curl -s -o /dev/null "$UP_ADDR/" && break || sleep 0.1
done

log "starting gateway proxy on $ADDR (registry + guardrail + log, upstream http://$UP_ADDR)"
"$FABRIC" gateway-proxy "$REPO_ROOT/registry" \
  --upstream "http://$UP_ADDR" \
  --addr "$ADDR" --log "$LOG" --guardrail "$GUARDRAIL" &
PROXY_PID=$!
for _ in $(seq 1 100); do
  curl -s -o /dev/null -X POST "$ADDR/" -H "X-Fabric-Agent: probe" && break || sleep 0.1
done
# The readiness probe above is itself a handled interaction, so it lands in the
# log. Truncate it now so only the scenario below is counted as evidence.
: > "$LOG"

# ---------------------------------------------------------------------------
log "1. FORWARD: qualified request is admitted and forwarded; agent gets the model reply"
# ---------------------------------------------------------------------------
code="$(post /clean release-reviewer "$(clean_body)")"
cat "$WORK/body.json"; echo
[ "$code" = "200" ] || fail "expected HTTP 200, got $code"
grep -qF "$CLEAN_REPLY" "$WORK/body.json" || fail "expected the upstream reply to be forwarded to the agent"
echo "PASS: qualified call forwarded, upstream reply returned"

# ---------------------------------------------------------------------------
log "2. BLOCK: unregistered agent -> 403 (call never forwarded)"
# ---------------------------------------------------------------------------
code="$(post /clean rogue "$(clean_body)")"
cat "$WORK/body.json"; echo
[ "$code" = "403" ] || fail "expected HTTP 403, got $code"
grep -q 'is not registered' "$WORK/body.json" || fail "expected registration denial reason"
echo "PASS: unregistered agent blocked before the upstream"

# ---------------------------------------------------------------------------
log "3. GUARDRAIL: request content carries a secret -> 403 (call never forwarded)"
# ---------------------------------------------------------------------------
code="$(post /clean release-reviewer "$(clean_body "deploy key $SECRET")")"
cat "$WORK/body.json"; echo
[ "$code" = "403" ] || fail "expected HTTP 403, got $code"
grep -q 'guardrail aws-secret-key' "$WORK/body.json" || fail "expected guardrail denial reason"
echo "PASS: sensitive request content blocked by guardrail"

# ---------------------------------------------------------------------------
log "4. MODEL: registered agent asks for an off-list model -> 403"
# ---------------------------------------------------------------------------
code="$(post /clean release-reviewer "$(clean_body 'please review PR 42' 'gpt-4o')")"
cat "$WORK/body.json"; echo
[ "$code" = "403" ] || fail "expected HTTP 403, got $code"
grep -q 'not qualified for model gpt-4o' "$WORK/body.json" || fail "expected model denial reason"
echo "PASS: off-list model blocked"

# ---------------------------------------------------------------------------
log "5. RESPONSE: upstream returns a secret -> proxy blocks it on the way back"
# ---------------------------------------------------------------------------
# The request itself is clean and qualified, so it forwards; the upstream's reply
# carries the secret, which the proxy must catch before it reaches the agent.
code="$(post /leak release-reviewer "$(clean_body)")"
cat "$WORK/body.json"; echo
[ "$code" = "403" ] || fail "expected HTTP 403 for a secret-bearing response, got $code"
grep -q 'guardrail aws-secret-key' "$WORK/body.json" || fail "expected guardrail denial reason on the response"
grep -qF "$SECRET" "$WORK/body.json" && fail "the secret-bearing response reached the agent"
echo "PASS: secret in the model's response blocked on the way back, never reaching the agent"

# ---------------------------------------------------------------------------
log "6. NO LEAK: the log records verdicts but never the raw input or response"
# ---------------------------------------------------------------------------
grep -qF "$SECRET" "$LOG" && fail "raw guardrail-caught content leaked into the log"
echo "PASS: log records the verdict but never the secret (request input or response)"

echo "--- interaction log ---"
cat "$LOG"

# ---------------------------------------------------------------------------
log "7. EVIDENCE: proxy log -> fabric trace -> ledger"
# ---------------------------------------------------------------------------
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

# The forwarded clean interaction logs two satisfied phases (input admission and a
# clean response), and the response-screened interaction logs a satisfied input
# (it forwarded) plus a not-satisfied output (the response was blocked) -> 3
# satisfied. The three request-side blocks (registration, guardrail, model) plus
# the one response block -> 4 not-satisfied. Every block being not-satisfied is
# the fidelity guarantee: a call the proxy blocked on content, model, or
# registration does not roll up as satisfied just because the agent was registered.
sat="$(grep -c '"result": "satisfied"' "$records" || true)"
notsat="$(grep -c '"result": "not-satisfied"' "$records" || true)"
[ "$sat" = "3" ]    || fail "expected 3 satisfied records, got $sat"
[ "$notsat" = "4" ] || fail "expected 4 not-satisfied records, got $notsat"
echo "PASS: 3 satisfied, 4 not-satisfied (registration + guardrail + model + response blocks all recorded)"

"$FABRIC" ledger verify "$ledger" || fail "ledger chain verification failed"
echo "PASS: ledger chain intact"

log "Phase 4 gateway-proxy e2e: all assertions passed"
