package evidence

import (
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/eval"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

func TestFromEvalGatePromotedVersionIsSatisfied(t *testing.T) {
	runJSON := `{
		"agent": "release-reviewer", "version": "1.0.0", "run-at": "2026-06-06T10:00:00Z",
		"results": [
			{"case": "inj-1", "suite": "prompt-injection", "passed": true},
			{"case": "leak-1", "suite": "data-leakage", "passed": true}
		]
	}`
	gate := eval.Gate{RequiredSuites: []string{"prompt-injection", "data-leakage"}, MaxFailures: 0}
	records, err := FromEvalGate([]byte(runJSON), gate, "eu-ai-act-15-accuracy-robustness")
	if err != nil {
		t.Fatalf("FromEvalGate: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.Result != oscal.StatusSatisfied {
		t.Errorf("expected satisfied, got %q", r.Result)
	}
	if r.Subject != "agent/release-reviewer/version/1.0.0" {
		t.Errorf("unexpected subject %q", r.Subject)
	}
	if r.Source != "eval-gate" {
		t.Errorf("unexpected source %q", r.Source)
	}
	if r.ObservedAt.IsZero() {
		t.Error("expected observed-at from run-at")
	}
	if r.Change != nil {
		t.Error("eval-gate records carry no change object")
	}
}

func TestFromEvalGateBlockedVersionIsNotSatisfied(t *testing.T) {
	runJSON := `{
		"agent": "release-reviewer", "version": "1.1.0", "run-at": "2026-06-06T10:00:00Z",
		"results": [{"case": "inj-1", "suite": "prompt-injection", "passed": false}]
	}`
	gate := eval.Gate{RequiredSuites: []string{"prompt-injection"}, MaxFailures: 0}
	records, err := FromEvalGate([]byte(runJSON), gate, "eu-ai-act-15-accuracy-robustness")
	if err != nil {
		t.Fatalf("FromEvalGate: %v", err)
	}
	if len(records) != 1 || records[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("expected one not-satisfied record, got %v", records)
	}
}

func TestFromEvalGateMalformedJSONIsError(t *testing.T) {
	if _, err := FromEvalGate([]byte(`{not json`), eval.Gate{}, "c"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
