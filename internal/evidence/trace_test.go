package evidence

import (
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/registry"
)

func traceRegistry() registry.Registry {
	return registry.Registry{
		Agents: []registry.Agent{{
			ID:      "release-reviewer",
			Version: "1.0.0",
			Owner:   "quality@example.com",
			Prompts: []string{"change-control-review"},
			Tools:   []string{"gh-pr-read"},
		}},
		Prompts: []registry.Prompt{{ID: "change-control-review", Version: "1.0.0"}},
		Tools:   []registry.Tool{{ID: "gh-pr-read", Version: "1.0.0"}},
	}
}

func TestFromAgentTracesConformingInteractionIsSatisfied(t *testing.T) {
	traces := `{"traces":[
		{"id":"t1","agent":"release-reviewer","prompt":"change-control-review","tools":["gh-pr-read"],"timestamp":"2026-06-06T09:14:00Z"}
	]}`
	records, err := FromAgentTraces([]byte(traces), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.Result != oscal.StatusSatisfied {
		t.Errorf("expected satisfied, got %q", r.Result)
	}
	if r.ControlID != "eu-ai-act-12-record-keeping" {
		t.Errorf("unexpected control id %q", r.ControlID)
	}
	if r.Subject != "agent/release-reviewer/trace/t1" {
		t.Errorf("unexpected subject %q", r.Subject)
	}
	if r.Source != "gateway/release-reviewer" {
		t.Errorf("unexpected source %q", r.Source)
	}
	if r.ObservedAt.IsZero() {
		t.Errorf("expected observed-at from trace timestamp")
	}
	if r.Change != nil {
		t.Errorf("trace records carry no change object")
	}
}

func TestFromAgentTracesUnregisteredAgentIsNotSatisfied(t *testing.T) {
	traces := `{"traces":[
		{"id":"t1","agent":"rogue-agent","prompt":"x","tools":[],"timestamp":"2026-06-06T09:14:00Z"}
	]}`
	records, _ := FromAgentTraces([]byte(traces), traceRegistry(), "eu-ai-act-12-record-keeping")
	if len(records) != 1 || records[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("expected one not-satisfied record, got %v", records)
	}
}

func TestFromAgentTracesUndeclaredPromptOrToolIsNotSatisfied(t *testing.T) {
	cases := map[string]string{
		"undeclared prompt": `{"traces":[{"id":"t1","agent":"release-reviewer","prompt":"ghost-prompt","tools":["gh-pr-read"],"timestamp":"2026-06-06T09:14:00Z"}]}`,
		"undeclared tool":   `{"traces":[{"id":"t1","agent":"release-reviewer","prompt":"change-control-review","tools":["rm-rf"],"timestamp":"2026-06-06T09:14:00Z"}]}`,
	}
	for name, traces := range cases {
		t.Run(name, func(t *testing.T) {
			records, err := FromAgentTraces([]byte(traces), traceRegistry(), "eu-ai-act-12-record-keeping")
			if err != nil {
				t.Fatalf("FromAgentTraces: %v", err)
			}
			if len(records) != 1 || records[0].Result != oscal.StatusNotSatisfied {
				t.Fatalf("expected one not-satisfied record, got %v", records)
			}
		})
	}
}

func TestFromAgentTracesMalformedJSONIsError(t *testing.T) {
	if _, err := FromAgentTraces([]byte(`{not json`), traceRegistry(), "c"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// The inline gateway writes its interaction log as JSON Lines (one object per
// line), not the {"traces":[...]} envelope. FromAgentTraces must consume that
// shape too, so what the gateway enforced inline rolls up as evidence with no
// reshaping step.
func TestFromAgentTracesAcceptsGatewayJSONLines(t *testing.T) {
	log := `{"id":"t1","agent":"release-reviewer","prompt":"change-control-review","tools":["gh-pr-read"],"timestamp":"2026-06-06T09:14:00Z","allowed":true}
{"id":"t2","agent":"rogue-agent","prompt":"x","tools":[],"timestamp":"2026-06-06T09:15:00Z","allowed":false,"reason":"agent rogue-agent is not registered"}`
	records, err := FromAgentTraces([]byte(log), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Result != oscal.StatusSatisfied {
		t.Errorf("record 0: expected satisfied, got %q", records[0].Result)
	}
	if records[0].Subject != "agent/release-reviewer/trace/t1" {
		t.Errorf("record 0: unexpected subject %q", records[0].Subject)
	}
	if records[1].Result != oscal.StatusNotSatisfied {
		t.Errorf("record 1: expected not-satisfied, got %q", records[1].Result)
	}
}

// A gateway can block an interaction on content (a guardrail match) even when the
// agent, prompt, and tools are all qualified. The gateway records that block as
// allowed:false in its log. Evidence must honor that recorded verdict: a request
// the gateway actually blocked must not roll up as satisfied just because it would
// have passed the registration check. Otherwise guardrail enforcement is invisible
// to the audit trail.
func TestFromAgentTracesHonorsRecordedGuardrailBlock(t *testing.T) {
	log := `{"id":"t1","agent":"release-reviewer","prompt":"change-control-review","tools":["gh-pr-read"],"timestamp":"2026-06-06T09:14:00Z","allowed":false,"reason":"content blocked by guardrail aws-secret-key"}`
	records, err := FromAgentTraces([]byte(log), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Result != oscal.StatusNotSatisfied {
		t.Errorf("a gateway-blocked interaction must be not-satisfied, got %q", records[0].Result)
	}
}

// A trace with no recorded verdict (the {"traces":[...]} envelope an OTel pipeline
// produces) carries no allowed field, so it must still be judged by the registry
// surface rather than defaulting to blocked.
func TestFromAgentTracesWithoutVerdictIsJudgedByRegistry(t *testing.T) {
	traces := `{"traces":[
		{"id":"t1","agent":"release-reviewer","prompt":"change-control-review","tools":["gh-pr-read"],"timestamp":"2026-06-06T09:14:00Z"}
	]}`
	records, err := FromAgentTraces([]byte(traces), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 1 || records[0].Result != oscal.StatusSatisfied {
		t.Fatalf("expected one satisfied record, got %v", records)
	}
}

// docs/05 says every agent action is traced with OpenTelemetry. FromAgentTraces
// must therefore consume the OTLP/JSON export shape (resourceSpans → scopeSpans →
// spans) directly, mapping each span's attributes to an interaction and its
// startTimeUnixNano to the observed time, so an OTel trace pipeline can feed the
// evidence ledger with no reshaping step. A conforming interaction is satisfied.
func TestFromAgentTracesAcceptsOTLPJSON(t *testing.T) {
	otlp := `{
		"resourceSpans": [{
			"scopeSpans": [{
				"spans": [{
					"spanId": "abc123",
					"name": "agent.interaction",
					"startTimeUnixNano": "1700000000000000000",
					"attributes": [
						{"key":"id","value":{"stringValue":"t1"}},
						{"key":"agent","value":{"stringValue":"release-reviewer"}},
						{"key":"prompt","value":{"stringValue":"change-control-review"}},
						{"key":"tools","value":{"arrayValue":{"values":[{"stringValue":"gh-pr-read"}]}}}
					]
				}]
			}]
		}]
	}`
	records, err := FromAgentTraces([]byte(otlp), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.Result != oscal.StatusSatisfied {
		t.Errorf("expected satisfied, got %q", r.Result)
	}
	if r.Subject != "agent/release-reviewer/trace/t1" {
		t.Errorf("unexpected subject %q", r.Subject)
	}
	if want := time.Unix(0, 1700000000000000000).UTC(); !r.ObservedAt.Equal(want) {
		t.Errorf("observed-at = %v, want %v (span startTimeUnixNano)", r.ObservedAt, want)
	}
}

// An OTLP span whose agent is unregistered (or that used an undeclared prompt or
// tool) is off-policy, judged by the registry surface exactly like the other
// shapes.
func TestFromAgentTracesOTLPUnregisteredAgentIsNotSatisfied(t *testing.T) {
	otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[{
		"spanId":"s1","startTimeUnixNano":"1700000000000000000",
		"attributes":[
			{"key":"agent","value":{"stringValue":"rogue-agent"}},
			{"key":"prompt","value":{"stringValue":"x"}}
		]
	}]}]}]}`
	records, err := FromAgentTraces([]byte(otlp), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 1 || records[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("expected one not-satisfied record, got %v", records)
	}
	// With no "id" attribute the interaction id falls back to the span id.
	if records[0].Subject != "agent/rogue-agent/trace/s1" {
		t.Errorf("expected the span id as the interaction id, got subject %q", records[0].Subject)
	}
}

// When the gateway emits its inline verdict as an OTLP boolean attribute, evidence
// must honor it: a span recorded as allowed:false is not-satisfied even when the
// agent, prompt, and tools are all qualified (a content-guardrail block).
func TestFromAgentTracesOTLPHonorsRecordedBlock(t *testing.T) {
	otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[{
		"spanId":"s1","startTimeUnixNano":"1700000000000000000",
		"attributes":[
			{"key":"id","value":{"stringValue":"t1"}},
			{"key":"agent","value":{"stringValue":"release-reviewer"}},
			{"key":"prompt","value":{"stringValue":"change-control-review"}},
			{"key":"tools","value":{"arrayValue":{"values":[{"stringValue":"gh-pr-read"}]}}},
			{"key":"allowed","value":{"boolValue":false}}
		]
	}]}]}]}`
	records, err := FromAgentTraces([]byte(otlp), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 1 || records[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("a gateway-blocked span must be not-satisfied, got %v", records)
	}
}

// OTLP nests spans under resourceSpans → scopeSpans → spans; every span across all
// of those nestings must be flattened into one record each.
func TestFromAgentTracesOTLPFlattensAllSpans(t *testing.T) {
	otlp := `{"resourceSpans":[
		{"scopeSpans":[{"spans":[
			{"spanId":"s1","startTimeUnixNano":"1700000000000000000","attributes":[
				{"key":"id","value":{"stringValue":"t1"}},
				{"key":"agent","value":{"stringValue":"release-reviewer"}},
				{"key":"prompt","value":{"stringValue":"change-control-review"}},
				{"key":"tools","value":{"arrayValue":{"values":[{"stringValue":"gh-pr-read"}]}}}
			]}
		]}]},
		{"scopeSpans":[{"spans":[
			{"spanId":"s2","startTimeUnixNano":"1700000001000000000","attributes":[
				{"key":"id","value":{"stringValue":"t2"}},
				{"key":"agent","value":{"stringValue":"rogue-agent"}},
				{"key":"prompt","value":{"stringValue":"x"}}
			]}
		]}]}
	]}`
	records, err := FromAgentTraces([]byte(otlp), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records (one per span), got %d", len(records))
	}
	if records[0].Result != oscal.StatusSatisfied || records[1].Result != oscal.StatusNotSatisfied {
		t.Errorf("unexpected results: %q, %q", records[0].Result, records[1].Result)
	}
}

// Blank lines in a JSON-lines log (e.g. a trailing newline) must be skipped, not
// treated as malformed records.
func TestFromAgentTracesSkipsBlankJSONLines(t *testing.T) {
	log := "\n{\"id\":\"t1\",\"agent\":\"release-reviewer\",\"prompt\":\"change-control-review\",\"tools\":[\"gh-pr-read\"],\"timestamp\":\"2026-06-06T09:14:00Z\"}\n\n"
	records, err := FromAgentTraces([]byte(log), traceRegistry(), "eu-ai-act-12-record-keeping")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}
