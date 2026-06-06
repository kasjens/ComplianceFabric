package registry

import (
	"sort"
	"testing"
)

func rulesFor(findings []Finding, artifactID string) []string {
	var rules []string
	for _, f := range findings {
		if f.ArtifactID == artifactID {
			rules = append(rules, f.Rule)
		}
	}
	sort.Strings(rules)
	return rules
}

func hasRule(findings []Finding, rule, artifactID string) bool {
	for _, f := range findings {
		if f.Rule == rule && f.ArtifactID == artifactID {
			return true
		}
	}
	return false
}

func TestValidCleanRegistryHasNoFindings(t *testing.T) {
	r := Registry{
		Agents: []Agent{{
			ID:          "release-reviewer",
			Version:     "1.0.0",
			Description: "Reviews release PRs",
			Model:       "claude-opus-4",
			Owner:       "quality@example.com",
			Prompts:     []string{"review-system"},
			Tools:       []string{"gh-pr-read"},
		}},
		Prompts: []Prompt{{ID: "review-system", Version: "1.0.0", Text: "You review PRs."}},
		Tools:   []Tool{{ID: "gh-pr-read", Version: "1.0.0", Description: "Reads PR metadata"}},
	}
	if got := Validate(r); len(got) != 0 {
		t.Fatalf("expected no findings, got %v", got)
	}
}

func TestMissingVersionFlaggedForEveryArtifactKind(t *testing.T) {
	r := Registry{
		Agents:  []Agent{{ID: "a", Owner: "o"}},
		Prompts: []Prompt{{ID: "p"}},
		Tools:   []Tool{{ID: "t"}},
	}
	got := Validate(r)
	if !hasRule(got, "missing-version", "a") {
		t.Errorf("expected missing-version for agent a, got %v", got)
	}
	if !hasRule(got, "missing-version", "p") {
		t.Errorf("expected missing-version for prompt p, got %v", got)
	}
	if !hasRule(got, "missing-version", "t") {
		t.Errorf("expected missing-version for tool t, got %v", got)
	}
}

func TestMissingOwnerFlaggedForAgent(t *testing.T) {
	r := Registry{Agents: []Agent{{ID: "a", Version: "1.0.0"}}}
	if !hasRule(Validate(r), "missing-owner", "a") {
		t.Errorf("expected missing-owner for agent a")
	}
}

func TestUnknownPromptAndToolReferencesFlagged(t *testing.T) {
	r := Registry{
		Agents: []Agent{{
			ID:      "a",
			Version: "1.0.0",
			Owner:   "o",
			Prompts: []string{"ghost-prompt"},
			Tools:   []string{"ghost-tool"},
		}},
	}
	got := Validate(r)
	if !hasRule(got, "unknown-prompt-ref", "a") {
		t.Errorf("expected unknown-prompt-ref for agent a, got %v", got)
	}
	if !hasRule(got, "unknown-tool-ref", "a") {
		t.Errorf("expected unknown-tool-ref for agent a, got %v", got)
	}
}

func TestDuplicateIDsFlaggedWithinEachKind(t *testing.T) {
	r := Registry{
		Agents:  []Agent{{ID: "dup", Version: "1.0.0", Owner: "o"}, {ID: "dup", Version: "1.0.0", Owner: "o"}},
		Prompts: []Prompt{{ID: "pdup", Version: "1.0.0"}, {ID: "pdup", Version: "1.0.0"}},
		Tools:   []Tool{{ID: "tdup", Version: "1.0.0"}, {ID: "tdup", Version: "1.0.0"}},
	}
	got := Validate(r)
	for _, id := range []string{"dup", "pdup", "tdup"} {
		if !hasRule(got, "duplicate-id", id) {
			t.Errorf("expected duplicate-id for %s, got %v", id, got)
		}
	}
}

func TestDuplicateIDReportedOncePerID(t *testing.T) {
	r := Registry{
		Agents: []Agent{
			{ID: "dup", Version: "1.0.0", Owner: "o"},
			{ID: "dup", Version: "1.0.0", Owner: "o"},
			{ID: "dup", Version: "1.0.0", Owner: "o"},
		},
	}
	rules := rulesFor(Validate(r), "dup")
	count := 0
	for _, r := range rules {
		if r == "duplicate-id" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected duplicate-id reported once, got %d (%v)", count, rules)
	}
}
