package collect

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// jsonPath renders a filesystem path for embedding in a JSON fixture. On Windows
// a path like C:\Users\... makes "\U" an invalid JSON escape, so the fixture fails
// to parse and the test fails for a reason that has nothing to do with what it is
// testing. Go accepts forward slashes on every platform.
func jsonPath(p string) string { return filepath.ToSlash(p) }

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// A well-formed config parses into a runtime Config: the interval is a duration,
// and each source's declarative fields are resolved into the producer Params.
func TestLoadConfigResolvesSources(t *testing.T) {
	dir := t.TempDir()
	sbomPolicy := writeFile(t, dir, "sbom-policy.json", `{"banned":[{"name":"log4j-core","version":""}]}`)
	cfg := writeFile(t, dir, "collect.json", `{
		"interval": "30s",
		"sources": [
			{"type":"drift","command":["kubectl","get","applications","-o","json"],"control":"annex11-11-periodic-evaluation"},
			{"type":"sbom","command":["syft","img","-o","cyclonedx-json"],"control":"cfr-part-11-10a-system-validation","sbom-policy-file":"`+jsonPath(sbomPolicy)+`"}
		]
	}`)

	got, err := LoadConfig(cfg)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got.Interval != 30*time.Second {
		t.Errorf("interval: got %v, want 30s", got.Interval)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(got.Sources))
	}
	if got.Sources[0].Params.ControlID != "annex11-11-periodic-evaluation" {
		t.Errorf("drift control id not resolved: %q", got.Sources[0].Params.ControlID)
	}
	if len(got.Sources[1].Params.SBOMPolicy.Banned) != 1 {
		t.Errorf("sbom policy file not resolved into Params")
	}
}

// An unknown producer type must fail at load time, not silently collect nothing.
func TestLoadConfigRejectsUnknownType(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "c.json", `{"interval":"1m","sources":[{"type":"nope","command":["x"]}]}`)
	if _, err := LoadConfig(cfg); err == nil {
		t.Fatal("expected an error for an unknown source type")
	}
}

// A source with no fetch command cannot be collected, so it is a config error.
func TestLoadConfigRejectsEmptyCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "c.json", `{"interval":"1m","sources":[{"type":"drift","command":[],"control":"c1"}]}`)
	if _, err := LoadConfig(cfg); err == nil {
		t.Fatal("expected an error for an empty command")
	}
}

// A malformed interval is a config error.
func TestLoadConfigRejectsBadInterval(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "c.json", `{"interval":"soon","sources":[{"type":"drift","command":["x"],"control":"c1"}]}`)
	if _, err := LoadConfig(cfg); err == nil {
		t.Fatal("expected an error for a malformed interval")
	}
}

// A referenced aux file that cannot be read is a config error, surfaced at load
// rather than on the first tick.
func TestLoadConfigRejectsMissingAuxFile(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "c.json", `{"interval":"1m","sources":[{"type":"sbom","command":["x"],"control":"c1","sbom-policy-file":"/no/such/file.json"}]}`)
	if _, err := LoadConfig(cfg); err == nil {
		t.Fatal("expected an error for a missing aux file")
	}
}
