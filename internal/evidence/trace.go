package evidence

import (
	"encoding/json"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/registry"
)

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
	var log struct {
		Traces []struct {
			ID        string    `json:"id"`
			Agent     string    `json:"agent"`
			Prompt    string    `json:"prompt"`
			Tools     []string  `json:"tools"`
			Timestamp time.Time `json:"timestamp"`
		} `json:"traces"`
	}
	if err := json.Unmarshal(tracesJSON, &log); err != nil {
		return nil, err
	}

	agents := make(map[string]registry.Agent, len(reg.Agents))
	for _, a := range reg.Agents {
		agents[a.ID] = a
	}

	var records []Record
	for _, tr := range log.Traces {
		result := oscal.StatusSatisfied
		if !conformsToRegistry(agents, tr.Agent, tr.Prompt, tr.Tools) {
			result = oscal.StatusNotSatisfied
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

// conformsToRegistry reports whether an interaction stayed within the agent's
// qualified surface: the agent is registered, the prompt is one it declares, and
// every tool used is one it declares.
func conformsToRegistry(agents map[string]registry.Agent, agentID, prompt string, tools []string) bool {
	agent, ok := agents[agentID]
	if !ok {
		return false
	}
	if !contains(agent.Prompts, prompt) {
		return false
	}
	for _, used := range tools {
		if !contains(agent.Tools, used) {
			return false
		}
	}
	return true
}

func contains(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}
