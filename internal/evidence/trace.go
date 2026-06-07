package evidence

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/gateway"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// traceRec is one interaction as it appears in either log shape: the
// {"traces":[...]} envelope or the gateway's JSON-lines log. Allowed is the
// gateway's recorded verdict; it is a pointer so an absent field (a raw trace with
// no verdict) is distinguishable from a recorded false (an interaction the gateway
// blocked).
type traceRec struct {
	ID        string    `json:"id"`
	Agent     string    `json:"agent"`
	Prompt    string    `json:"prompt"`
	Tools     []string  `json:"tools"`
	Timestamp time.Time `json:"timestamp"`
	Allowed   *bool     `json:"allowed"`
}

// FromAgentTraces turns a gateway interaction log into evidence records keyed to
// the given control, evaluating each interaction against the agent registry. An
// interaction is satisfied only when it stayed within the agent's qualified
// surface: the agent is registered, the prompt it used is one the agent
// declares, and every tool it invoked is one the agent declares. An interaction
// by an unregistered agent, or one that used an undeclared prompt or tool, is
// off-policy (not-satisfied). This is what ties the Phase 4 registry to runtime:
// the registry is the qualified surface, the trace is what actually happened.
// One record is produced per trace.
func FromAgentTraces(tracesJSON []byte, reg registry.Registry, controlID string) ([]Record, error) {
	traces, err := parseTraces(tracesJSON)
	if err != nil {
		return nil, err
	}

	var records []Record
	for _, tr := range traces {
		// The gateway's inline admission decision and this post-hoc evidence
		// judgment are the same question, so they share one definition of
		// "qualified": a trace the gateway would have blocked is exactly a trace
		// that rolls up as not-satisfied.
		result := oscal.StatusSatisfied
		switch {
		case tr.Allowed != nil && !*tr.Allowed:
			// The gateway recorded that it blocked this interaction (registration
			// or content guardrail). Honor that verdict so the block the gateway
			// enforced is faithful in the evidence — re-deriving from the registry
			// alone would silently pass a content-blocked request the registry
			// would have qualified.
			result = oscal.StatusNotSatisfied
		default:
			decision := gateway.Decide(reg, gateway.Request{
				ID:     tr.ID,
				Agent:  tr.Agent,
				Prompt: tr.Prompt,
				Tools:  tr.Tools,
			})
			if !decision.Allowed {
				result = oscal.StatusNotSatisfied
			}
		}
		records = append(records, Record{
			ControlID:  controlID,
			Subject:    "agent/" + tr.Agent + "/trace/" + tr.ID,
			Result:     result,
			ObservedAt: tr.Timestamp.UTC(),
			Source:     "gateway/" + tr.Agent,
		})
	}
	return records, nil
}

// parseTraces accepts either interaction-log shape: the batch envelope
// {"traces":[...]} or the inline gateway's JSON-lines log (one interaction
// object per line). Detecting the shape rather than demanding one lets the same
// evidence producer consume a gateway log directly, so what the gateway enforced
// inline rolls up as evidence with no reshaping step.
func parseTraces(data []byte) ([]traceRec, error) {
	trimmed := bytes.TrimSpace(data)

	// A single, valid JSON object is either the envelope (has a "traces" array)
	// or one JSON-lines record. A multi-line JSON-lines log is not valid as one
	// JSON value, so it falls through to line-by-line parsing below.
	var probe map[string]json.RawMessage
	if json.Unmarshal(trimmed, &probe) == nil {
		if raw, ok := probe["traces"]; ok {
			var recs []traceRec
			if err := json.Unmarshal(raw, &recs); err != nil {
				return nil, err
			}
			return recs, nil
		}
		var tr traceRec
		if err := json.Unmarshal(trimmed, &tr); err != nil {
			return nil, err
		}
		return []traceRec{tr}, nil
	}

	var recs []traceRec
	for _, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var tr traceRec
		if err := json.Unmarshal(line, &tr); err != nil {
			return nil, err
		}
		recs = append(recs, tr)
	}
	return recs, nil
}
