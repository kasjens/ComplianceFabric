package gateway

import (
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// gatewayRegistry is the qualified surface the decision core judges against: one
// registered agent with a single declared prompt and two declared tools.
func gatewayRegistry() registry.Registry {
	return registry.Registry{
		Agents: []registry.Agent{{
			ID:      "release-reviewer",
			Version: "1.0.0",
			Owner:   "quality@example.com",
			Prompts: []string{"change-control-review"},
			Tools:   []string{"gh-pr-read", "ledger-append"},
		}},
		Prompts: []registry.Prompt{{ID: "change-control-review", Version: "1.0.0"}},
		Tools: []registry.Tool{
			{ID: "gh-pr-read", Version: "1.0.0"},
			{ID: "ledger-append", Version: "1.0.0"},
		},
	}
}

func TestDecide(t *testing.T) {
	reg := gatewayRegistry()

	tests := []struct {
		name        string
		req         Request
		wantAllowed bool
		wantReason  string
	}{
		{
			name: "conforming request is allowed",
			req: Request{
				ID:     "r1",
				Agent:  "release-reviewer",
				Prompt: "change-control-review",
				Tools:  []string{"gh-pr-read", "ledger-append"},
			},
			wantAllowed: true,
			wantReason:  "",
		},
		{
			name: "unregistered agent is denied",
			req: Request{
				ID:     "r2",
				Agent:  "rogue-agent",
				Prompt: "change-control-review",
				Tools:  []string{"gh-pr-read"},
			},
			wantAllowed: false,
			wantReason:  "agent rogue-agent is not registered",
		},
		{
			name: "undeclared prompt is denied",
			req: Request{
				ID:     "r3",
				Agent:  "release-reviewer",
				Prompt: "jailbreak",
				Tools:  []string{"gh-pr-read"},
			},
			wantAllowed: false,
			wantReason:  "agent release-reviewer is not qualified for prompt jailbreak",
		},
		{
			name: "undeclared tool is denied",
			req: Request{
				ID:     "r4",
				Agent:  "release-reviewer",
				Prompt: "change-control-review",
				Tools:  []string{"gh-pr-read", "shell-exec"},
			},
			wantAllowed: false,
			wantReason:  "agent release-reviewer is not qualified for tool shell-exec",
		},
		{
			name: "no tools used is allowed",
			req: Request{
				ID:     "r5",
				Agent:  "release-reviewer",
				Prompt: "change-control-review",
			},
			wantAllowed: true,
			wantReason:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(reg, tt.req)
			if got.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", got.Allowed, tt.wantAllowed)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}

// modelPinnedRegistry is the qualified surface for the model allow-list: the same
// agent as gatewayRegistry but pinned to a specific model, so the gateway can
// screen which model a request asks to call.
func modelPinnedRegistry() registry.Registry {
	reg := gatewayRegistry()
	reg.Agents[0].Model = "claude-opus-4"
	return reg
}

// The model allow-list screens the model a request declares against the model the
// agent is qualified for. A request asking for a different model is blocked; one
// asking for the qualified model passes; one that declares no model is not
// model-screened (the gateway can only screen what the caller asserts, and the
// post-hoc trace-evidence path re-derives without a model), so the registry,
// prompt, and tool checks still apply but the model check does not fire.
func TestDecideModelAllowList(t *testing.T) {
	reg := modelPinnedRegistry()
	base := Request{Agent: "release-reviewer", Prompt: "change-control-review", Tools: []string{"gh-pr-read"}}

	tests := []struct {
		name        string
		model       string
		wantAllowed bool
		wantReason  string
	}{
		{name: "qualified model is allowed", model: "claude-opus-4", wantAllowed: true},
		{name: "off-list model is blocked", model: "gpt-4o", wantAllowed: false,
			wantReason: "agent release-reviewer is not qualified for model gpt-4o"},
		{name: "undeclared model is not screened", model: "", wantAllowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			req.Model = tt.model
			got := Decide(reg, req)
			if got.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", got.Allowed, tt.wantAllowed)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}
