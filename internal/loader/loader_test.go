package loader

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadReadsEachModelType(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "catalogs", "annex11.json"), `{
		"id": "annex11",
		"metadata": {"title": "Annex 11", "version": "1.0.0"},
		"controls": [{"id": "annex11-9-audit-trail", "title": "Audit trail"}]
	}`)
	writeFile(t, filepath.Join(root, "profiles", "baseline.json"), `{
		"metadata": {"title": "Baseline", "version": "1.0.0"},
		"imports": [{"href": "annex11", "include-controls": ["annex11-9-audit-trail"]}]
	}`)
	writeFile(t, filepath.Join(root, "component-definitions", "kyverno.json"), `{
		"metadata": {"title": "Kyverno", "version": "1.0.0"},
		"mappings": [{"control-id": "annex11-9-audit-trail", "implemented-by": [
			{"component": "platform-logging", "policy-id": "require-audit-logging"}
		]}]
	}`)

	b, err := Load(root)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(b.Catalogs) != 1 {
		t.Errorf("catalogs = %d, want 1", len(b.Catalogs))
	}
	if len(b.Profiles) != 1 {
		t.Errorf("profiles = %d, want 1", len(b.Profiles))
	}
	if len(b.ComponentDefinitions) != 1 {
		t.Errorf("component definitions = %d, want 1", len(b.ComponentDefinitions))
	}
	if len(b.Catalogs) == 1 && b.Catalogs[0].ID != "annex11" {
		t.Errorf("catalog ID = %q, want %q", b.Catalogs[0].ID, "annex11")
	}
}

func TestLoadReadsCrosswalks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "catalogs", "annex11.json"), `{
		"id": "annex11",
		"metadata": {"title": "Annex 11", "version": "1.0.0"},
		"controls": [{"id": "annex11-9-audit-trail", "title": "Audit trail"}]
	}`)
	writeFile(t, filepath.Join(root, "crosswalks", "dora.json"), `{
		"metadata": {"title": "DORA crosswalk", "version": "0.1.0"},
		"mappings": [{"control": "dora-9-4-d-audit-trail", "satisfied-by": ["annex11-9-audit-trail"]}]
	}`)

	b, err := Load(root)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(b.Crosswalks) != 1 {
		t.Fatalf("crosswalks = %d, want 1", len(b.Crosswalks))
	}
	cw := b.Crosswalks[0]
	if len(cw.Mappings) != 1 || cw.Mappings[0].Control != "dora-9-4-d-audit-trail" {
		t.Errorf("crosswalk mappings = %+v, want one mapping for dora-9-4-d-audit-trail", cw.Mappings)
	}
	if len(cw.Mappings) == 1 && (len(cw.Mappings[0].SatisfiedBy) != 1 || cw.Mappings[0].SatisfiedBy[0] != "annex11-9-audit-trail") {
		t.Errorf("crosswalk satisfied-by = %+v, want [annex11-9-audit-trail]", cw.Mappings[0].SatisfiedBy)
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "catalogs", "broken.json"), `{ not valid json `)

	if _, err := Load(root); err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}
