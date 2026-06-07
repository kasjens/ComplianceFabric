package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServerInlineEnforcement(t *testing.T) {
	fixed := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		body           string
		wantStatus     int
		wantAllowed    bool
		wantReasonPart string
	}{
		{
			name:        "conforming request is admitted",
			body:        `{"id":"r1","agent":"release-reviewer","prompt":"change-control-review","tools":["gh-pr-read"]}`,
			wantStatus:  http.StatusOK,
			wantAllowed: true,
		},
		{
			name:           "unregistered agent is blocked",
			body:           `{"id":"r2","agent":"rogue","prompt":"change-control-review"}`,
			wantStatus:     http.StatusForbidden,
			wantAllowed:    false,
			wantReasonPart: "not registered",
		},
		{
			name:           "undeclared tool is blocked",
			body:           `{"id":"r3","agent":"release-reviewer","prompt":"change-control-review","tools":["shell-exec"]}`,
			wantStatus:     http.StatusForbidden,
			wantAllowed:    false,
			wantReasonPart: "not qualified for tool shell-exec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			srv := &Server{
				Registry: gatewayRegistry(),
				Log:      &logBuf,
				Now:      func() time.Time { return fixed },
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/decide", strings.NewReader(tt.body))
			srv.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var dec Decision
			if err := json.Unmarshal(rec.Body.Bytes(), &dec); err != nil {
				t.Fatalf("decode response: %v (body=%q)", err, rec.Body.String())
			}
			if dec.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", dec.Allowed, tt.wantAllowed)
			}
			if tt.wantReasonPart != "" && !strings.Contains(dec.Reason, tt.wantReasonPart) {
				t.Errorf("Reason = %q, want substring %q", dec.Reason, tt.wantReasonPart)
			}

			// Every handled request, admitted or blocked, must leave exactly one
			// interaction-log line that FromAgentTraces can later consume.
			logged := strings.TrimSpace(logBuf.String())
			if strings.Count(logged, "\n") != 0 {
				t.Errorf("expected exactly one log line, got %q", logged)
			}
			var entry struct {
				ID        string    `json:"id"`
				Agent     string    `json:"agent"`
				Prompt    string    `json:"prompt"`
				Timestamp time.Time `json:"timestamp"`
				Allowed   bool      `json:"allowed"`
			}
			if err := json.Unmarshal([]byte(logged), &entry); err != nil {
				t.Fatalf("decode log line: %v (line=%q)", err, logged)
			}
			if !entry.Timestamp.Equal(fixed) {
				t.Errorf("log timestamp = %v, want %v", entry.Timestamp, fixed)
			}
			if entry.Allowed != tt.wantAllowed {
				t.Errorf("log Allowed = %v, want %v", entry.Allowed, tt.wantAllowed)
			}
		})
	}
}

func TestServerScreensContentAfterRegistration(t *testing.T) {
	fixed := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	guard, err := CompileGuardrail(GuardrailPolicy{Rules: []GuardrailRule{
		{Name: "aws-secret-key", Pattern: `AKIA[0-9A-Z]{16}`},
	}})
	if err != nil {
		t.Fatalf("CompileGuardrail: %v", err)
	}

	var logBuf bytes.Buffer
	srv := &Server{
		Registry:  gatewayRegistry(),
		Guardrail: guard,
		Log:       &logBuf,
		Now:       func() time.Time { return fixed },
	}

	// A registered agent using its declared prompt/tools, but whose input carries
	// a secret, must be blocked by the guardrail even though the registry check
	// passes.
	body := `{"id":"r9","agent":"release-reviewer","prompt":"change-control-review",
		"tools":["gh-pr-read"],"input":"use AKIAIOSFODNN7EXAMPLE to read the bucket"}`
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/decide", strings.NewReader(body)))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	var dec Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &dec); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if dec.Allowed {
		t.Errorf("Allowed = true, want false (content carries a secret)")
	}
	if !strings.Contains(dec.Reason, "guardrail aws-secret-key") {
		t.Errorf("Reason = %q, want it to name the guardrail", dec.Reason)
	}

	// The interaction log must record the block. It must NOT contain the raw
	// input, which may itself be the sensitive data the guardrail caught.
	logged := strings.TrimSpace(logBuf.String())
	if strings.Contains(logged, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("interaction log leaked the screened input: %q", logged)
	}
	var entry struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.Unmarshal([]byte(logged), &entry); err != nil {
		t.Fatalf("decode log line: %v", err)
	}
	if entry.Allowed {
		t.Errorf("log Allowed = true, want false")
	}
}

// The gateway screens generated output, not just input: a registered agent's
// output that carries a secret is blocked at /output, and the interaction log
// records the verdict without ever leaking the raw output (which may itself be the
// sensitive data the guardrail caught). A clean output is admitted.
func TestServerScreensOutput(t *testing.T) {
	fixed := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	guard, err := CompileGuardrail(GuardrailPolicy{Rules: []GuardrailRule{
		{Name: "aws-secret-key", Pattern: `AKIA[0-9A-Z]{16}`},
	}})
	if err != nil {
		t.Fatalf("CompileGuardrail: %v", err)
	}

	post := func(t *testing.T, body string) (*httptest.ResponseRecorder, string) {
		t.Helper()
		var logBuf bytes.Buffer
		srv := &Server{
			Registry:  gatewayRegistry(),
			Guardrail: guard,
			Log:       &logBuf,
			Now:       func() time.Time { return fixed },
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/output", strings.NewReader(body)))
		return rec, strings.TrimSpace(logBuf.String())
	}

	t.Run("output carrying a secret is blocked and not leaked", func(t *testing.T) {
		rec, logged := post(t, `{"id":"o1","agent":"release-reviewer","prompt":"change-control-review",
			"output":"the deploy key is AKIAIOSFODNN7EXAMPLE"}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
		var dec Decision
		if err := json.Unmarshal(rec.Body.Bytes(), &dec); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if dec.Allowed {
			t.Errorf("Allowed = true, want false (output carries a secret)")
		}
		if !strings.Contains(dec.Reason, "guardrail aws-secret-key") {
			t.Errorf("Reason = %q, want it to name the guardrail", dec.Reason)
		}
		if strings.Contains(logged, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("interaction log leaked the screened output: %q", logged)
		}
		var entry struct {
			Phase   string `json:"phase"`
			Allowed bool   `json:"allowed"`
		}
		if err := json.Unmarshal([]byte(logged), &entry); err != nil {
			t.Fatalf("decode log line: %v (line=%q)", err, logged)
		}
		if entry.Allowed {
			t.Errorf("log Allowed = true, want false")
		}
		if entry.Phase != "output" {
			t.Errorf("log phase = %q, want %q", entry.Phase, "output")
		}
	})

	t.Run("clean output is admitted", func(t *testing.T) {
		rec, logged := post(t, `{"id":"o2","agent":"release-reviewer","prompt":"change-control-review",
			"output":"PR 42 satisfies change control"}`)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		var dec Decision
		if err := json.Unmarshal(rec.Body.Bytes(), &dec); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !dec.Allowed {
			t.Errorf("Allowed = false, want true (clean output)")
		}
		if logged == "" {
			t.Errorf("expected the admitted output to be logged")
		}
	})
}

// The limiter is the third gate: a registered agent running a declared prompt
// with clean input is still blocked once it exhausts its per-window budget, and
// the block is recorded in the interaction log like any other denial.
func TestServerEnforcesRateLimit(t *testing.T) {
	fixed := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	srv := &Server{
		Registry: gatewayRegistry(),
		Limiter:  NewLimiter(map[string]Limits{"release-reviewer": {MaxRequests: 1, Window: time.Minute}}),
		Log:      &logBuf,
		Now:      func() time.Time { return fixed },
	}

	body := `{"id":"r1","agent":"release-reviewer","prompt":"change-control-review","tools":["gh-pr-read"]}`
	post := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/decide", strings.NewReader(body)))
		return rec
	}

	// First request fits the budget.
	if rec := post(); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Second request in the same window exceeds the request budget.
	rec := post()
	if rec.Code != http.StatusForbidden {
		t.Errorf("second request status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	var dec Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &dec); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if dec.Allowed {
		t.Errorf("Allowed = true, want false (rate limit exceeded)")
	}
	if !strings.Contains(dec.Reason, "rate") {
		t.Errorf("Reason = %q, want a rate-limit reason", dec.Reason)
	}

	// Both interactions are logged; the second records the block.
	lines := strings.Split(strings.TrimSpace(logBuf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %d: %q", len(lines), logBuf.String())
	}
	var last struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &last); err != nil {
		t.Fatalf("decode log line: %v", err)
	}
	if last.Allowed {
		t.Errorf("second log line Allowed = true, want false")
	}
}

// A request that fails an earlier gate (registry or guardrail) must not consume
// limiter budget: the limiter only charges interactions that would otherwise be
// admitted, so a blocked request cannot exhaust a budget that a later valid one
// needs.
func TestServerLimiterChargesOnlyAdmittedRequests(t *testing.T) {
	fixed := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	srv := &Server{
		Registry: gatewayRegistry(),
		Limiter:  NewLimiter(map[string]Limits{"release-reviewer": {MaxRequests: 1, Window: time.Minute}}),
		Now:      func() time.Time { return fixed },
	}

	// A request denied by the registry (undeclared tool) must not draw down the
	// budget.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/decide",
		strings.NewReader(`{"id":"x","agent":"release-reviewer","prompt":"change-control-review","tools":["shell-exec"]}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("undeclared-tool request status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// The agent's single budgeted request is still available.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/decide",
		strings.NewReader(`{"id":"ok","agent":"release-reviewer","prompt":"change-control-review","tools":["gh-pr-read"]}`)))
	if rec.Code != http.StatusOK {
		t.Errorf("valid request status = %d, want %d (blocked request wrongly consumed budget)", rec.Code, http.StatusOK)
	}
}

func TestServerRejectsBadInput(t *testing.T) {
	srv := &Server{Registry: gatewayRegistry()}

	t.Run("non-POST is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/decide", nil)
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("malformed body is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/decide", strings.NewReader("{not json"))
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})
}
