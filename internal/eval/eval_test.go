package eval

import (
	"strings"
	"testing"
)

func run() Run {
	return Run{
		Agent:   "release-reviewer",
		Version: "1.0.0",
		Results: []Result{
			{Case: "inj-1", Suite: "prompt-injection", Passed: true},
			{Case: "leak-1", Suite: "data-leakage", Passed: true},
			{Case: "qual-1", Suite: "output-quality", Passed: true},
		},
	}
}

func TestGatePromotesWhenAllPassAndRequiredSuitesPresent(t *testing.T) {
	gate := Gate{RequiredSuites: []string{"prompt-injection", "data-leakage"}, MaxFailures: 0}
	d := gate.Evaluate(run())
	if !d.Promote {
		t.Fatalf("expected promote, got blocked: %v", d.Reasons)
	}
	if d.Failures != 0 {
		t.Errorf("expected 0 failures, got %d", d.Failures)
	}
	if d.Agent != "release-reviewer" || d.Version != "1.0.0" {
		t.Errorf("decision did not carry agent/version: %+v", d)
	}
}

func TestGateBlocksWhenFailuresExceedMax(t *testing.T) {
	r := run()
	r.Results[0].Passed = false
	gate := Gate{MaxFailures: 0}
	d := gate.Evaluate(r)
	if d.Promote {
		t.Fatal("expected block when a case fails and MaxFailures is 0")
	}
	if d.Failures != 1 {
		t.Errorf("expected 1 failure, got %d", d.Failures)
	}
	if len(d.Reasons) == 0 {
		t.Error("expected a blocking reason")
	}
}

func TestGateAllowsFailuresUpToMax(t *testing.T) {
	r := run()
	r.Results[0].Passed = false
	gate := Gate{MaxFailures: 1}
	if d := gate.Evaluate(r); !d.Promote {
		t.Fatalf("expected promote when failures within budget, got %v", d.Reasons)
	}
}

func TestGateBlocksWhenRequiredSuiteNotEvaluated(t *testing.T) {
	gate := Gate{RequiredSuites: []string{"prompt-injection", "cybersecurity"}, MaxFailures: 0}
	d := gate.Evaluate(run())
	if d.Promote {
		t.Fatal("expected block when a required suite was not evaluated")
	}
	joined := strings.Join(d.Reasons, "; ")
	if !strings.Contains(joined, "cybersecurity") {
		t.Errorf("expected reason naming the missing suite, got %q", joined)
	}
}
