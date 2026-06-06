package evidence

import (
	"testing"

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
