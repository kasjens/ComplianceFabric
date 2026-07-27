package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// REPRODUCTION — Workstream R.2, plan items 1.1 and 1.5. Expected to FAIL
// against cac9f78. Both drive the real Proxy against a real upstream.

// testRegistry qualifies the test agent for the prompt it sends, so the response
// path is what these tests exercise rather than the admission gates.
func testRegistry() registry.Registry {
	return registry.Registry{
		Agents: []registry.Agent{{
			ID:      "release-reviewer",
			Prompts: []string{"summarise-findings"},
		}},
	}
}

// jsonUnicodeEscape renders every rune of s as a JSON \uXXXX escape.
func jsonUnicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "\\u%04X", r)
	}
	return b.String()
}

// proxyTo builds a Proxy in front of upstream with the AKIA guardrail active and
// a registry that qualifies the test agent, so the response path is what is
// under test rather than the admission gates.
func proxyTo(t *testing.T, upstream *httptest.Server) *httptest.Server {
	t.Helper()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{
		Registry:  testRegistry(),
		Guardrail: akiaGuardrail(t),
		Limiter:   NewLimiter(map[string]Limits{}),
		Upstream:  u,
	}
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	return ps
}

// callProxy sends a clean request through the proxy and returns the response body
// the agent receives.
func callProxy(t *testing.T, proxy *httptest.Server) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-x","messages":[{"role":"user","content":"summarise"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderAgent, "release-reviewer")
	req.Header.Set(HeaderPrompt, "summarise-findings")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// 1.1 — SSE events are screened in isolation with no overlap window, and
// token-by-token emission is exactly how an LLM streams text. A secret split
// across two events matches neither event, so every byte is released and the
// agent reassembles the key. finish() then logs the stream as allowed.
func TestRepro11SecretSplitAcrossSSEEventsMustNotReachAgent(t *testing.T) {
	cases := []struct {
		name   string
		chunks []string
	}{
		{"split across 2 events", []string{"AKIA", "IOSFODNN7EXAMPLE"}},
		{"split across 3 events", []string{"AKIA", "IOSFODNN7", "EXAMPLE"}},
		{"split one character in", []string{"A", "KIAIOSFODNN7EXAMPLE"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				for _, c := range tc.chunks {
					// Each event is individually clean under AKIA[0-9A-Z]{16}.
					io.WriteString(w, "data: {\"delta\":{\"text\":\""+c+"\"}}\n\n")
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
				}
			}))
			defer upstream.Close()

			got := callProxy(t, proxyTo(t, upstream))

			// Reassemble the way the agent's SSE parser does.
			var reassembled strings.Builder
			for _, line := range strings.Split(string(got), "\n") {
				line = strings.TrimPrefix(strings.TrimSpace(line), "data: ")
				if line == "" {
					continue
				}
				var ev struct {
					Delta struct {
						Text string `json:"text"`
					} `json:"delta"`
				}
				if json.Unmarshal([]byte(line), &ev) == nil {
					reassembled.WriteString(ev.Delta.Text)
				}
			}

			if strings.Contains(reassembled.String(), secret) {
				t.Errorf("agent reassembled the full secret %q from individually-clean SSE events; "+
					"the guardrail never saw it", secret)
			}
		})
	}
}

// 1.5 — the request is screened DECODED but the response is screened as raw JSON
// bytes. A \u-escaped secret does not match the raw body, yet the agent's JSON
// parser reconstructs it.
func TestRepro15EscapedSecretInBufferedResponseMustNotReachAgent(t *testing.T) {
	// The secret written entirely as JSON unicode escapes: it decodes back to the
	// secret but shares no literal bytes with it.
	escaped := jsonUnicodeEscape(secret)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"text":"`+escaped+`"}`)
	}))
	defer upstream.Close()

	got := callProxy(t, proxyTo(t, upstream))

	var payload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(got, &payload); err != nil {
		// A block replaced the body with a Decision — that is the desired outcome.
		return
	}
	if strings.Contains(payload.Text, secret) {
		t.Errorf("agent decoded the secret %q from a \\u-escaped response the guardrail "+
			"screened as raw bytes and allowed", secret)
	}
}
