package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func writeJSON(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadReadsArtifactsFromDirectoryTree(t *testing.T) {
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "agents", "reviewer.json"), `{
		"id": "release-reviewer", "version": "1.0.0", "owner": "quality@example.com",
		"prompts": ["review-system"], "tools": ["gh-pr-read"]
	}`)
	writeJSON(t, filepath.Join(root, "prompts", "review.json"), `{
		"id": "review-system", "version": "1.0.0", "text": "You review PRs."
	}`)
	writeJSON(t, filepath.Join(root, "tools", "gh.json"), `{
		"id": "gh-pr-read", "version": "1.0.0", "description": "Reads PR metadata"
	}`)

	r, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.Agents) != 1 || len(r.Prompts) != 1 || len(r.Tools) != 1 {
		t.Fatalf("expected 1 of each artifact, got %d agents, %d prompts, %d tools",
			len(r.Agents), len(r.Prompts), len(r.Tools))
	}
	if r.Agents[0].ID != "release-reviewer" {
		t.Errorf("unexpected agent id %q", r.Agents[0].ID)
	}
	if got := Validate(r); len(got) != 0 {
		t.Errorf("loaded registry should validate clean, got %v", got)
	}
}

func TestLoadMissingSubdirIsEmptyNotError(t *testing.T) {
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "tools", "gh.json"), `{"id": "t", "version": "1.0.0"}`)
	r, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.Agents) != 0 || len(r.Prompts) != 0 || len(r.Tools) != 1 {
		t.Fatalf("expected only the tool, got %d agents, %d prompts, %d tools",
			len(r.Agents), len(r.Prompts), len(r.Tools))
	}
}

func TestLoadMalformedJSONIsError(t *testing.T) {
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "agents", "bad.json"), `{not json`)
	if _, err := Load(root); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}
