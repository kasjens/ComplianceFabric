// Package gateway is the runtime admission point for AI agent interactions. It
// holds the single decision the Phase 4 agent layer turns on: given an incoming
// request and the agent registry, did the request stay within the agent's
// qualified surface? The same judgment that evidence.FromAgentTraces makes after
// the fact over a log, the gateway makes inline, before the interaction is
// allowed to proceed. Keeping it here as pure logic lets both the inline
// enforcement path and the post-hoc evidence path share one definition of
// "qualified", so a request the gateway would block is exactly a trace that
// rolls up as not-satisfied.
package gateway

import "github.com/kasjens/ComplianceFabric/internal/registry"

// Request is one agent interaction presented to the gateway: which agent, the
// model and prompt it intends to run, the tools it intends to use, and the input
// content it intends to send. The registry check (Decide) uses the agent, model,
// prompt, and tools; the content guardrail screens Input.
type Request struct {
	ID     string   `json:"id"`
	Agent  string   `json:"agent"`
	Model  string   `json:"model"`
	Prompt string   `json:"prompt"`
	Tools  []string `json:"tools"`
	Input  string   `json:"input"`
	// Cost is the caller-asserted cost of this interaction, charged against the
	// agent's per-window cost budget by the limiter. Zero when the caller asserts
	// no cost; a request that declares no cost still counts toward a request-rate
	// budget.
	Cost float64 `json:"cost,omitempty"`
	// RequireDeclaredModel demands that a model-pinned agent state its model, and
	// is set on the live proxy path where an undeclared model can still resolve
	// upstream (Azure OpenAI takes the deployment from the URL path). It stays
	// false for post-hoc re-derivation from a trace, where a historical
	// interaction may simply not have recorded one and denying it would
	// manufacture a lapse that never happened.
	RequireDeclaredModel bool `json:"-"`
}

// Decision is the gateway's verdict on a request. When Allowed is false, Reason
// states the first qualification the request failed.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// Decide judges a request against the registry's qualified surface. A request is
// allowed only when the agent is registered, the prompt it runs is one the agent
// declares, the model it asks to call is the one the agent is qualified for, and
// every tool it uses is one the agent declares. The first failed qualification
// determines the denial reason.
//
// The model check is an allow-list against the agent's single qualified model. It
// fires only when the request declares a model and the agent pins one: a request
// that declares no model is not model-screened (the gateway can only screen what
// the caller asserts, and the post-hoc trace-evidence path re-derives this same
// decision without a model), and an agent with no pinned model constrains nothing
// on the model axis.
func Decide(reg registry.Registry, req Request) Decision {
	var agent registry.Agent
	found := false
	for _, a := range reg.Agents {
		if a.ID == req.Agent {
			agent = a
			found = true
			break
		}
	}
	if !found {
		return Decision{Allowed: false, Reason: "agent " + req.Agent + " is not registered"}
	}
	if !contains(agent.Prompts, req.Prompt) {
		return Decision{Allowed: false, Reason: "agent " + req.Agent + " is not qualified for prompt " + req.Prompt}
	}
	if agent.Model != "" && req.Model != "" && req.Model != agent.Model {
		return Decision{Allowed: false, Reason: "agent " + req.Agent + " is not qualified for model " + req.Model}
	}
	// An agent pinned to a model must DECLARE one. The old carve-out for an
	// undeclared model assumed the model always travels in the body, but Azure
	// OpenAI carries the deployment in the URL path — so omitting the body field
	// skipped the allow-list while the request still reached a real model.
	if agent.Model != "" && req.Model == "" && req.RequireDeclaredModel {
		return Decision{Allowed: false, Reason: "agent " + req.Agent +
			" is pinned to model " + agent.Model + " but its request declares no model"}
	}
	for _, used := range req.Tools {
		if !contains(agent.Tools, used) {
			return Decision{Allowed: false, Reason: "agent " + req.Agent + " is not qualified for tool " + used}
		}
	}
	return Decision{Allowed: true}
}

// contains reports whether want is in set.
func contains(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}
