package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// An OpenAI-style chat-completion body the release-reviewer agent is qualified
// for: model gpt-4 (the agent pins no model, so any model passes), the declared
// gh-pr-read tool, and a clean user message.
const cleanChatBody = `{"model":"gpt-4",
	"messages":[{"role":"user","content":"review PR 42"}],
	"tools":[{"type":"function","function":{"name":"gh-pr-read"}}]}`

func proxyRequest(agent, prompt, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	if agent != "" {
		r.Header.Set(HeaderAgent, agent)
	}
	if prompt != "" {
		r.Header.Set(HeaderPrompt, prompt)
	}
	return r
}

func TestRequestFromHTTPExtractsIdentityModelToolsInput(t *testing.T) {
	r := proxyRequest("release-reviewer", "change-control-review", cleanChatBody)
	r.Header.Set(HeaderCost, "0.5")

	req, err := RequestFromHTTP(r)
	if err != nil {
		t.Fatalf("RequestFromHTTP: %v", err)
	}
	if req.Agent != "release-reviewer" {
		t.Errorf("Agent = %q, want release-reviewer", req.Agent)
	}
	if req.Prompt != "change-control-review" {
		t.Errorf("Prompt = %q, want change-control-review", req.Prompt)
	}
	if req.Model != "gpt-4" {
		t.Errorf("Model = %q, want gpt-4", req.Model)
	}
	if len(req.Tools) != 1 || req.Tools[0] != "gh-pr-read" {
		t.Errorf("Tools = %v, want [gh-pr-read]", req.Tools)
	}
	if !strings.Contains(req.Input, "review PR 42") {
		t.Errorf("Input = %q, want it to carry the message text", req.Input)
	}
	if req.Cost != 0.5 {
		t.Errorf("Cost = %v, want 0.5", req.Cost)
	}
}

// Anthropic tool blocks name the tool at the top level rather than under a
// function object; both shapes must be recovered so the tool allow-list applies
// regardless of which API the agent calls.
func TestRequestFromHTTPReadsAnthropicToolNames(t *testing.T) {
	body := `{"model":"claude","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],
		"tools":[{"name":"gh-pr-read"}]}`
	req, err := RequestFromHTTP(proxyRequest("release-reviewer", "change-control-review", body))
	if err != nil {
		t.Fatalf("RequestFromHTTP: %v", err)
	}
	if len(req.Tools) != 1 || req.Tools[0] != "gh-pr-read" {
		t.Errorf("Tools = %v, want [gh-pr-read]", req.Tools)
	}
	if !strings.Contains(req.Input, "hi") {
		t.Errorf("Input = %q, want the text block content", req.Input)
	}
}

func TestRequestFromHTTPRequiresAgentHeader(t *testing.T) {
	if _, err := RequestFromHTTP(proxyRequest("", "p", cleanChatBody)); err == nil {
		t.Fatal("a request with no agent identity should be an error (fail closed)")
	}
}

func TestRequestFromHTTPRejectsMalformedBody(t *testing.T) {
	if _, err := RequestFromHTTP(proxyRequest("release-reviewer", "p", "{not json")); err == nil {
		t.Fatal("a malformed body should be an error")
	}
}

func TestRequestFromHTTPRejectsBadCost(t *testing.T) {
	r := proxyRequest("release-reviewer", "p", cleanChatBody)
	r.Header.Set(HeaderCost, "lots")
	if _, err := RequestFromHTTP(r); err == nil {
		t.Fatal("an unparseable cost header should be an error")
	}
}

// Extraction reads the body to recover the request, but must leave it readable so
// the proxy can still forward the original payload upstream unchanged.
func TestRequestFromHTTPLeavesBodyReadable(t *testing.T) {
	r := proxyRequest("release-reviewer", "change-control-review", cleanChatBody)
	if _, err := RequestFromHTTP(r); err != nil {
		t.Fatalf("RequestFromHTTP: %v", err)
	}
	forwarded, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("re-read body: %v", err)
	}
	if string(forwarded) != cleanChatBody {
		t.Errorf("forwarded body = %q, want the original payload unchanged", forwarded)
	}
}

// newUpstream is a fake LLM endpoint that records whether it was reached.
func newUpstream(t *testing.T, hits *int) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}
	return u
}

func TestProxyForwardsAdmittedRequestUpstream(t *testing.T) {
	hits := 0
	p := &Proxy{Registry: gatewayRegistry(), Upstream: newUpstream(t, &hits)}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, proxyRequest("release-reviewer", "change-control-review", cleanChatBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if hits != 1 {
		t.Errorf("upstream hit %d times, want 1", hits)
	}
	if got := rec.Body.String(); got != "upstream-ok" {
		t.Errorf("body = %q, want the upstream response", got)
	}
}

func TestProxyBlocksUnregisteredAgentWithoutForwarding(t *testing.T) {
	hits := 0
	p := &Proxy{Registry: gatewayRegistry(), Upstream: newUpstream(t, &hits)}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, proxyRequest("rogue", "change-control-review", cleanChatBody))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if hits != 0 {
		t.Errorf("a blocked request reached the upstream %d times, want 0", hits)
	}
	var dec Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &dec); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if dec.Allowed || !strings.Contains(dec.Reason, "not registered") {
		t.Errorf("decision = %+v, want a not-registered denial", dec)
	}
}

func TestProxyBlocksOnGuardrailWithoutForwarding(t *testing.T) {
	hits := 0
	guard, err := CompileGuardrail(GuardrailPolicy{Rules: []GuardrailRule{
		{Name: "aws-secret-key", Pattern: `AKIA[0-9A-Z]{16}`},
	}})
	if err != nil {
		t.Fatalf("CompileGuardrail: %v", err)
	}
	p := &Proxy{Registry: gatewayRegistry(), Guardrail: guard, Upstream: newUpstream(t, &hits)}

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"use AKIAIOSFODNN7EXAMPLE"}],
		"tools":[{"type":"function","function":{"name":"gh-pr-read"}}]}`
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, proxyRequest("release-reviewer", "change-control-review", body))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if hits != 0 {
		t.Errorf("a guardrail-blocked request reached the upstream %d times, want 0", hits)
	}
}

func TestProxyEnforcesRateLimit(t *testing.T) {
	hits := 0
	p := &Proxy{
		Registry: gatewayRegistry(),
		Limiter:  NewLimiter(map[string]Limits{"release-reviewer": {MaxRequests: 1, Window: time.Minute}}),
		Upstream: newUpstream(t, &hits),
		Now:      func() time.Time { return at(0) },
	}

	first := httptest.NewRecorder()
	p.ServeHTTP(first, proxyRequest("release-reviewer", "change-control-review", cleanChatBody))
	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", first.Code, http.StatusOK)
	}

	second := httptest.NewRecorder()
	p.ServeHTTP(second, proxyRequest("release-reviewer", "change-control-review", cleanChatBody))
	if second.Code != http.StatusForbidden {
		t.Errorf("second request status = %d, want %d", second.Code, http.StatusForbidden)
	}
	if hits != 1 {
		t.Errorf("upstream hit %d times, want 1 (the rate-limited request must not forward)", hits)
	}
}

// newUpstreamBody is a fake LLM endpoint that returns a fixed response body, used
// to exercise response-side screening.
func newUpstreamBody(t *testing.T, body string) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}
	return u
}

// findLogPhase returns the parsed log line whose phase matches, failing if none.
func findLogPhase(t *testing.T, logged, phase string) struct {
	Phase   string `json:"phase"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
} {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		var e struct {
			Phase   string `json:"phase"`
			Allowed bool   `json:"allowed"`
			Reason  string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		if e.Phase == phase {
			return e
		}
	}
	t.Fatalf("no %s-phase log line in %q", phase, logged)
	return struct {
		Phase   string `json:"phase"`
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}{}
}

// The proxy screens the upstream's response, not just the request: an upstream
// reply carrying a secret is blocked before it reaches the agent (403, the secret
// never forwarded), and a phase:"output" verdict is logged without leaking it.
func TestProxyScreensUpstreamResponse(t *testing.T) {
	guard, err := CompileGuardrail(GuardrailPolicy{Rules: []GuardrailRule{
		{Name: "aws-secret-key", Pattern: `AKIA[0-9A-Z]{16}`},
	}})
	if err != nil {
		t.Fatalf("CompileGuardrail: %v", err)
	}
	var logBuf bytes.Buffer
	p := &Proxy{
		Registry:  gatewayRegistry(),
		Guardrail: guard,
		Upstream:  newUpstreamBody(t, "the deploy key is AKIAIOSFODNN7EXAMPLE"),
		Log:       &logBuf,
		Now:       func() time.Time { return at(0) },
	}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, proxyRequest("release-reviewer", "change-control-review", cleanChatBody))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (response carried a secret)", rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("the secret-bearing response reached the agent: %q", rec.Body.String())
	}
	if strings.Contains(logBuf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("the proxy log leaked the screened output: %q", logBuf.String())
	}
	out := findLogPhase(t, logBuf.String(), "output")
	if out.Allowed || !strings.Contains(out.Reason, "guardrail") {
		t.Errorf("output log = %+v, want a guardrail denial", out)
	}
}

// A clean upstream response passes through unchanged, and the proxy records a
// passing phase:"output" verdict alongside the input admission.
func TestProxyForwardsCleanUpstreamResponse(t *testing.T) {
	guard, err := CompileGuardrail(GuardrailPolicy{Rules: []GuardrailRule{
		{Name: "aws-secret-key", Pattern: `AKIA[0-9A-Z]{16}`},
	}})
	if err != nil {
		t.Fatalf("CompileGuardrail: %v", err)
	}
	var logBuf bytes.Buffer
	p := &Proxy{
		Registry:  gatewayRegistry(),
		Guardrail: guard,
		Upstream:  newUpstreamBody(t, "PR 42 satisfies change control"),
		Log:       &logBuf,
		Now:       func() time.Time { return at(0) },
	}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, proxyRequest("release-reviewer", "change-control-review", cleanChatBody))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "PR 42 satisfies change control" {
		t.Errorf("body = %q, want the clean upstream response unchanged", got)
	}
	if out := findLogPhase(t, logBuf.String(), "output"); !out.Allowed {
		t.Errorf("output log = %+v, want allowed", out)
	}
}

func TestProxyRejectsRequestWithoutIdentity(t *testing.T) {
	hits := 0
	p := &Proxy{Registry: gatewayRegistry(), Upstream: newUpstream(t, &hits)}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, proxyRequest("", "change-control-review", cleanChatBody))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (no agent identity)", rec.Code, http.StatusBadRequest)
	}
	if hits != 0 {
		t.Errorf("an unidentified request reached the upstream %d times, want 0", hits)
	}
}

func TestProxyLogsHandledInteraction(t *testing.T) {
	hits := 0
	var logBuf bytes.Buffer
	fixed := at(0)
	p := &Proxy{
		Registry: gatewayRegistry(),
		Upstream: newUpstream(t, &hits),
		Log:      &logBuf,
		Now:      func() time.Time { return fixed },
	}

	p.ServeHTTP(httptest.NewRecorder(), proxyRequest("release-reviewer", "change-control-review", cleanChatBody))

	logged := strings.TrimSpace(logBuf.String())
	var entry struct {
		Agent     string    `json:"agent"`
		Model     string    `json:"model"`
		Phase     string    `json:"phase"`
		Timestamp time.Time `json:"timestamp"`
		Allowed   bool      `json:"allowed"`
	}
	if err := json.Unmarshal([]byte(logged), &entry); err != nil {
		t.Fatalf("decode log line: %v (line=%q)", err, logged)
	}
	if entry.Agent != "release-reviewer" || entry.Model != "gpt-4" || !entry.Allowed {
		t.Errorf("log entry = %+v, want release-reviewer/gpt-4/allowed", entry)
	}
	if !entry.Timestamp.Equal(fixed) {
		t.Errorf("log timestamp = %v, want %v", entry.Timestamp, fixed)
	}
	// The proxy log must never carry the screened message content.
	if strings.Contains(logged, "review PR 42") {
		t.Errorf("proxy log leaked the request input: %q", logged)
	}
}
