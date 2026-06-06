// Package eval models the evaluation gate an AI agent version must pass before
// it may promote to production. An agent is non-deterministic, so it is held to
// a fixed test set — prompt-injection resistance, data-leakage checks, output
// quality — and a version that fails the gate does not promote. The gate policy
// is authoritative and separate from the run it judges: the run reports what
// happened, the gate decides whether that is good enough.
package eval

import (
	"strconv"
	"strings"
	"time"
)

// Result is the outcome of one evaluation case.
type Result struct {
	Case   string `json:"case"`
	Suite  string `json:"suite"`
	Passed bool   `json:"passed"`
}

// Run is the result of evaluating one agent version against the test set.
type Run struct {
	Agent   string    `json:"agent"`
	Version string    `json:"version"`
	RunAt   time.Time `json:"run-at"`
	Results []Result  `json:"results"`
}

// Gate is the promotion policy: which evaluation suites must have been run, and
// how many failing cases are tolerated. A zero MaxFailures means every case must
// pass.
type Gate struct {
	RequiredSuites []string `json:"required-suites"`
	MaxFailures    int      `json:"max-failures"`
}

// Decision is the gate's verdict for one agent version.
type Decision struct {
	Agent    string
	Version  string
	Promote  bool
	Failures int
	Reasons  []string
}

// Evaluate judges a run against the gate. The version may promote only when
// every required suite was actually evaluated and the number of failing cases
// does not exceed the gate's budget. Each blocking condition is reported as a
// reason.
func (g Gate) Evaluate(run Run) Decision {
	evaluated := make(map[string]bool)
	failures := 0
	for _, r := range run.Results {
		evaluated[r.Suite] = true
		if !r.Passed {
			failures++
		}
	}

	var reasons []string
	for _, suite := range g.RequiredSuites {
		if !evaluated[suite] {
			reasons = append(reasons, "required suite "+suite+" was not evaluated")
		}
	}
	if failures > g.MaxFailures {
		reasons = append(reasons, strconv.Itoa(failures)+" case(s) failed, gate allows at most "+strconv.Itoa(g.MaxFailures))
	}

	return Decision{
		Agent:    run.Agent,
		Version:  run.Version,
		Promote:  len(reasons) == 0,
		Failures: failures,
		Reasons:  reasons,
	}
}

// Summary renders the decision's reasons as a single line, empty when promoting.
func (d Decision) Summary() string {
	return strings.Join(d.Reasons, "; ")
}
