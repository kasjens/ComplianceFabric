package evidence

import (
	"bytes"
	"encoding/json"
	"strconv"
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

// parseTraces accepts any of three interaction-log shapes: the batch envelope
// {"traces":[...]}, the OTLP/JSON trace export ({"resourceSpans":[...]}) an
// OpenTelemetry pipeline produces, or the inline gateway's JSON-lines log (one
// interaction object per line). Detecting the shape rather than demanding one lets
// the same evidence producer consume a gateway log or an OTel export directly, so
// what the gateway enforced inline rolls up as evidence with no reshaping step.
func parseTraces(data []byte) ([]traceRec, error) {
	trimmed := bytes.TrimSpace(data)

	// A single, valid JSON object is the envelope (has a "traces" array), an
	// OTLP/JSON export (has "resourceSpans"), or one JSON-lines record. A
	// multi-line JSON-lines log is not valid as one JSON value, so it falls
	// through to line-by-line parsing below.
	var probe map[string]json.RawMessage
	if json.Unmarshal(trimmed, &probe) == nil {
		if raw, ok := probe["traces"]; ok {
			var recs []traceRec
			if err := json.Unmarshal(raw, &recs); err != nil {
				return nil, err
			}
			return recs, nil
		}
		if _, ok := probe["resourceSpans"]; ok {
			return parseOTLPTraces(trimmed)
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

// OTLP/JSON trace export shapes (a subset of OpenTelemetry's
// ExportTraceServiceRequest), enough to read one agent interaction per span.
// Per the OTLP/JSON encoding, 64-bit fields such as the unix-nano timestamps are
// strings, so StartTimeUnixNano is a string parsed below.
type otlpExport struct {
	ResourceSpans []struct {
		ScopeSpans []struct {
			Spans []otlpSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type otlpSpan struct {
	SpanID            string         `json:"spanId"`
	Name              string         `json:"name"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes"`
}

type otlpKeyValue struct {
	Key   string `json:"key"`
	Value struct {
		StringValue *string `json:"stringValue"`
		BoolValue   *bool   `json:"boolValue"`
		ArrayValue  *struct {
			Values []struct {
				StringValue *string `json:"stringValue"`
			} `json:"values"`
		} `json:"arrayValue"`
	} `json:"value"`
}

// parseOTLPTraces flattens an OTLP/JSON trace export into interaction records.
// Each span is one interaction: its attributes carry the agent, prompt, tools, an
// optional interaction id (falling back to the span id), and an optional recorded
// verdict (the gateway's allowed bool), and its start time is the observed time.
// The attribute keys mirror the gateway log's field names, so a span and a
// JSON-lines record describe the same interaction in two transports.
func parseOTLPTraces(data []byte) ([]traceRec, error) {
	var export otlpExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, err
	}

	var recs []traceRec
	for _, rs := range export.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, span := range ss.Spans {
				recs = append(recs, spanToTrace(span))
			}
		}
	}
	return recs, nil
}

// spanToTrace maps one OTLP span to an interaction record, reading the fabric
// interaction attributes from the span and its start time as the timestamp.
func spanToTrace(span otlpSpan) traceRec {
	tr := traceRec{ID: span.SpanID}
	for _, attr := range span.Attributes {
		switch attr.Key {
		case "id":
			if attr.Value.StringValue != nil {
				tr.ID = *attr.Value.StringValue
			}
		case "agent":
			if attr.Value.StringValue != nil {
				tr.Agent = *attr.Value.StringValue
			}
		case "prompt":
			if attr.Value.StringValue != nil {
				tr.Prompt = *attr.Value.StringValue
			}
		case "tools":
			if attr.Value.ArrayValue != nil {
				for _, v := range attr.Value.ArrayValue.Values {
					if v.StringValue != nil {
						tr.Tools = append(tr.Tools, *v.StringValue)
					}
				}
			}
		case "allowed":
			tr.Allowed = attr.Value.BoolValue
		}
	}
	if nanos, err := strconv.ParseInt(span.StartTimeUnixNano, 10, 64); err == nil && nanos > 0 {
		tr.Timestamp = time.Unix(0, nanos).UTC()
	}
	return tr
}
