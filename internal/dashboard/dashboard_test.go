package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

func rec(control, result string, observedAt string) evidence.Record {
	t, _ := time.Parse(time.RFC3339, observedAt)
	return evidence.Record{ControlID: control, Subject: "s", Result: result, ObservedAt: t, Source: "test"}
}

// staticSource returns a fixed set of records, standing in for the production
// ledger read.
func staticSource(records ...evidence.Record) func() ([]evidence.Record, error) {
	return func() ([]evidence.Record, error) { return records, nil }
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// The root path renders the live posture as an HTML page naming each control and
// its current status.
func TestHandlerServesHTMLPosture(t *testing.T) {
	h := Handler{Source: staticSource(
		rec("annex11-9-audit-trail", oscal.StatusSatisfied, "2026-06-07T10:00:00Z"),
	)}
	w := get(t, h, http.MethodGet, "/")
	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"annex11-9-audit-trail", "satisfied"} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML posture missing %q:\n%s", want, body)
		}
	}
}

// The JSON endpoint exposes the same rollup machine-readably, with a summary a
// monitor can gate on.
func TestHandlerServesJSONPosture(t *testing.T) {
	h := Handler{Source: staticSource(
		rec("c-ok", oscal.StatusSatisfied, "2026-06-07T10:00:00Z"),
		rec("c-gap", oscal.StatusNotSatisfied, "2026-06-07T10:00:00Z"),
	)}
	w := get(t, h, http.MethodGet, "/posture.json")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /posture.json status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var resp struct {
		Controls []struct {
			ControlID string `json:"control-id"`
			Status    string `json:"status"`
		} `json:"controls"`
		Summary struct {
			Total     int `json:"total"`
			Satisfied int `json:"satisfied"`
			Gaps      int `json:"gaps"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("posture.json is not valid JSON: %v\n%s", err, w.Body.String())
	}
	if len(resp.Controls) != 2 {
		t.Fatalf("want 2 controls, got %d", len(resp.Controls))
	}
	if resp.Summary.Total != 2 || resp.Summary.Satisfied != 1 || resp.Summary.Gaps != 1 {
		t.Errorf("summary = %+v, want total 2 / satisfied 1 / gaps 1", resp.Summary)
	}
}

// A control whose latest status is not-satisfied is shown as an open gap.
func TestHandlerHighlightsGaps(t *testing.T) {
	h := Handler{Source: staticSource(
		rec("c-gap", oscal.StatusNotSatisfied, "2026-06-07T10:00:00Z"),
	)}
	body := get(t, h, http.MethodGet, "/").Body.String()
	if !strings.Contains(body, "c-gap") || !strings.Contains(body, "not-satisfied") {
		t.Errorf("HTML posture should surface the gap:\n%s", body)
	}
}

// The dashboard re-reads its source on every request, so a record appended after
// the page first loads is reflected on the next request (the "live" property).
func TestHandlerReReadsSourceEachRequest(t *testing.T) {
	records := []evidence.Record{rec("c1", oscal.StatusSatisfied, "2026-06-07T10:00:00Z")}
	h := Handler{Source: func() ([]evidence.Record, error) { return records, nil }}

	if body := get(t, h, http.MethodGet, "/").Body.String(); strings.Contains(body, "c2") {
		t.Fatalf("did not expect c2 before it is appended:\n%s", body)
	}
	records = append(records, rec("c2", oscal.StatusSatisfied, "2026-06-07T11:00:00Z"))
	if body := get(t, h, http.MethodGet, "/").Body.String(); !strings.Contains(body, "c2") {
		t.Errorf("expected the newly appended c2 on a later request:\n%s", body)
	}
}

// The trend endpoint exposes the coverage-over-time series machine-readably, one
// point per observed moment.
func TestHandlerServesTrendJSON(t *testing.T) {
	h := Handler{Source: staticSource(
		rec("c1", oscal.StatusSatisfied, "2026-06-07T10:00:00Z"),
		rec("c2", oscal.StatusNotSatisfied, "2026-06-07T11:00:00Z"),
	)}
	w := get(t, h, http.MethodGet, "/trend.json")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /trend.json status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var resp struct {
		Points []struct {
			At        string `json:"at"`
			Total     int    `json:"total"`
			Satisfied int    `json:"satisfied"`
		} `json:"points"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("trend.json is not valid JSON: %v\n%s", err, w.Body.String())
	}
	if len(resp.Points) != 2 {
		t.Fatalf("want 2 trend points, got %d", len(resp.Points))
	}
	if resp.Points[0].Satisfied != 1 || resp.Points[1].Total != 2 || resp.Points[1].Satisfied != 1 {
		t.Errorf("trend points = %+v, want coverage to rise to 2/1", resp.Points)
	}
}

// The HTML dashboard renders a coverage-trend section (an inline SVG sparkline),
// so the trend is visible alongside the current rollup.
func TestHandlerHTMLIncludesTrend(t *testing.T) {
	h := Handler{Source: staticSource(
		rec("c1", oscal.StatusSatisfied, "2026-06-07T10:00:00Z"),
		rec("c2", oscal.StatusNotSatisfied, "2026-06-07T11:00:00Z"),
	)}
	body := get(t, h, http.MethodGet, "/").Body.String()
	if !strings.Contains(body, "Coverage trend") {
		t.Errorf("HTML missing the coverage-trend section:\n%s", body)
	}
	if !strings.Contains(body, "<svg") || !strings.Contains(body, "<polyline") {
		t.Errorf("HTML missing the trend sparkline SVG:\n%s", body)
	}
}

func TestHandlerRejectsNonGET(t *testing.T) {
	h := Handler{Source: staticSource()}
	if code := get(t, h, http.MethodPost, "/").Code; code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status = %d, want 405", code)
	}
}

func TestHandlerUnknownPathIs404(t *testing.T) {
	h := Handler{Source: staticSource()}
	if code := get(t, h, http.MethodGet, "/nope").Code; code != http.StatusNotFound {
		t.Fatalf("GET /nope status = %d, want 404", code)
	}
}

func TestHandlerSourceErrorIs500(t *testing.T) {
	h := Handler{Source: func() ([]evidence.Record, error) {
		return nil, errFailed
	}}
	if code := get(t, h, http.MethodGet, "/").Code; code != http.StatusInternalServerError {
		t.Fatalf("GET / with a failing source status = %d, want 500", code)
	}
}

var errFailed = &sourceErr{}

type sourceErr struct{}

func (*sourceErr) Error() string { return "ledger unreadable" }
