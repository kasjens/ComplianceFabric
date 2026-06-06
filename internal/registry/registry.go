// Package registry models AI agents and the prompts and tools they use as
// versioned, governable artifacts. An agent is only as trustworthy as the
// prompt and tool surface it was qualified against, so the registry pins each
// of those to a version and an accountable owner — the same attributability
// GxP expects of any change to a validated system. Validate checks the
// internal consistency of a registry before anything downstream (gateway
// policy, evaluation gates) relies on it.
package registry

// Agent is a deployable AI agent pinned to a model, an owner, and the specific
// prompt and tool artifacts it is qualified to use.
type Agent struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Model       string   `json:"model"`
	Owner       string   `json:"owner"`
	Prompts     []string `json:"prompts"`
	Tools       []string `json:"tools"`
}

// Prompt is a versioned system or task prompt an agent may reference.
type Prompt struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Text    string `json:"text"`
}

// Tool is a versioned capability an agent may be granted.
type Tool struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// Registry is the set of agent, prompt, and tool artifacts governed together.
type Registry struct {
	Agents  []Agent  `json:"agents"`
	Prompts []Prompt `json:"prompts"`
	Tools   []Tool   `json:"tools"`
}

// Severity classifies a finding.
type Severity string

const (
	Error Severity = "error"
)

// Finding is one problem discovered while validating a registry.
type Finding struct {
	Rule       string
	Severity   Severity
	ArtifactID string
	Message    string
}

// Validate checks the registry for internal consistency and returns every
// finding. An empty slice means every artifact is versioned, every agent has an
// owner, every reference resolves, and no ID is duplicated.
func Validate(r Registry) []Finding {
	var findings []Finding
	findings = append(findings, checkVersions(r)...)
	findings = append(findings, checkOwners(r)...)
	findings = append(findings, checkReferences(r)...)
	findings = append(findings, checkDuplicateIDs(r)...)
	return findings
}

// checkVersions flags any artifact, of any kind, that carries no version. An
// unversioned artifact cannot be qualified or pinned.
func checkVersions(r Registry) []Finding {
	var findings []Finding
	for _, a := range r.Agents {
		if a.Version == "" {
			findings = append(findings, Finding{
				Rule:       "missing-version",
				Severity:   Error,
				ArtifactID: a.ID,
				Message:    "agent " + a.ID + " has no version",
			})
		}
	}
	for _, p := range r.Prompts {
		if p.Version == "" {
			findings = append(findings, Finding{
				Rule:       "missing-version",
				Severity:   Error,
				ArtifactID: p.ID,
				Message:    "prompt " + p.ID + " has no version",
			})
		}
	}
	for _, t := range r.Tools {
		if t.Version == "" {
			findings = append(findings, Finding{
				Rule:       "missing-version",
				Severity:   Error,
				ArtifactID: t.ID,
				Message:    "tool " + t.ID + " has no version",
			})
		}
	}
	return findings
}

// checkOwners flags any agent without an accountable owner. Ownership is what
// makes an agent's behavior attributable.
func checkOwners(r Registry) []Finding {
	var findings []Finding
	for _, a := range r.Agents {
		if a.Owner == "" {
			findings = append(findings, Finding{
				Rule:       "missing-owner",
				Severity:   Error,
				ArtifactID: a.ID,
				Message:    "agent " + a.ID + " has no owner",
			})
		}
	}
	return findings
}

// checkReferences flags an agent that references a prompt or tool ID no artifact
// in the registry defines. A dangling reference means the agent was qualified
// against something that is not pinned.
func checkReferences(r Registry) []Finding {
	prompts := make(map[string]bool, len(r.Prompts))
	for _, p := range r.Prompts {
		prompts[p.ID] = true
	}
	tools := make(map[string]bool, len(r.Tools))
	for _, t := range r.Tools {
		tools[t.ID] = true
	}

	var findings []Finding
	for _, a := range r.Agents {
		for _, id := range a.Prompts {
			if !prompts[id] {
				findings = append(findings, Finding{
					Rule:       "unknown-prompt-ref",
					Severity:   Error,
					ArtifactID: a.ID,
					Message:    "agent " + a.ID + " references unknown prompt " + id,
				})
			}
		}
		for _, id := range a.Tools {
			if !tools[id] {
				findings = append(findings, Finding{
					Rule:       "unknown-tool-ref",
					Severity:   Error,
					ArtifactID: a.ID,
					Message:    "agent " + a.ID + " references unknown tool " + id,
				})
			}
		}
	}
	return findings
}

// checkDuplicateIDs flags an ID that appears more than once within a kind. Each
// duplicated ID is reported once.
func checkDuplicateIDs(r Registry) []Finding {
	var findings []Finding
	flag := func(ids []string, kind string) {
		seen := make(map[string]int, len(ids))
		for _, id := range ids {
			seen[id]++
		}
		for id, n := range seen {
			if n > 1 {
				findings = append(findings, Finding{
					Rule:       "duplicate-id",
					Severity:   Error,
					ArtifactID: id,
					Message:    kind + " " + id + " is defined more than once",
				})
			}
		}
	}

	agentIDs := make([]string, len(r.Agents))
	for i, a := range r.Agents {
		agentIDs[i] = a.ID
	}
	promptIDs := make([]string, len(r.Prompts))
	for i, p := range r.Prompts {
		promptIDs[i] = p.ID
	}
	toolIDs := make([]string, len(r.Tools))
	for i, t := range r.Tools {
		toolIDs[i] = t.ID
	}
	flag(agentIDs, "agent")
	flag(promptIDs, "prompt")
	flag(toolIDs, "tool")
	return findings
}
