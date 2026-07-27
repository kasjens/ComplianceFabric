package release

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
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

// cycloneDXSBOM is a CycloneDX SBOM as syft emits it, inventorying one image.
const cycloneDXSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "timestamp": "2026-06-07T10:00:00Z",
    "component": { "type": "container", "name": "registry.example/mes", "version": "1.4.2" }
  },
  "components": [
    { "type": "library", "name": "openssl", "version": "3.0.8" }
  ]
}`

// A release manifest reads each declared artifact file, runs its producer, and
// returns every record (no dedup: a release ledger is fresh). A clean SBOM
// against a policy that bans nothing present yields one satisfied record.
func TestManifestEvidenceRunsProducers(t *testing.T) {
	dir := t.TempDir()
	sbom := writeFile(t, dir, "sbom.json", cycloneDXSBOM)
	policy := writeFile(t, dir, "policy.json", `{"banned":[{"name":"log4j-core","version":""}]}`)
	manifest := writeFile(t, dir, "release.json", `{
		"release": "mes-1.4.2",
		"sources": [
			{"type":"sbom","file":"`+jsonPath(sbom)+`","control":"cfr-part-11-10a-system-validation","sbom-policy-file":"`+jsonPath(policy)+`"}
		]
	}`)

	m, err := LoadManifest(manifest)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	records, err := m.Evidence()
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(records), records)
	}
	if records[0].Result != oscal.StatusSatisfied {
		t.Errorf("result = %q, want satisfied", records[0].Result)
	}
	if records[0].ControlID != "cfr-part-11-10a-system-validation" {
		t.Errorf("control id = %q", records[0].ControlID)
	}
}

// A banned component present in the release SBOM yields a not-satisfied record,
// which Blocking surfaces as a release-blocking finding.
func TestBlockingSurfacesNotSatisfied(t *testing.T) {
	dir := t.TempDir()
	sbom := writeFile(t, dir, "sbom.json", cycloneDXSBOM)
	policy := writeFile(t, dir, "policy.json", `{"banned":[{"name":"openssl","version":"3.0.8"}]}`)
	manifest := writeFile(t, dir, "release.json", `{
		"sources": [
			{"type":"sbom","file":"`+jsonPath(sbom)+`","control":"cfr-part-11-10a-system-validation","sbom-policy-file":"`+jsonPath(policy)+`"}
		]
	}`)

	m, err := LoadManifest(manifest)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	records, err := m.Evidence()
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}
	blocking := Blocking(records)
	if len(blocking) == 0 {
		t.Fatal("expected the banned component to block the release")
	}
	for _, r := range blocking {
		if r.Result == oscal.StatusSatisfied {
			t.Errorf("Blocking returned a satisfied record: %+v", r)
		}
	}
}

// Blocking is empty when every record is satisfied, so a clean release clears.
func TestBlockingEmptyWhenAllSatisfied(t *testing.T) {
	records := []evidence.Record{
		{ControlID: "c1", Result: oscal.StatusSatisfied},
		{ControlID: "c2", Result: oscal.StatusSatisfied},
	}
	if got := Blocking(records); len(got) != 0 {
		t.Errorf("expected no blocking records, got %+v", got)
	}
}

// An unknown producer type fails at load, not when the gate runs.
func TestLoadManifestRejectsUnknownType(t *testing.T) {
	dir := t.TempDir()
	m := writeFile(t, dir, "release.json", `{"sources":[{"type":"nope","file":"x.json"}]}`)
	if _, err := LoadManifest(m); err == nil {
		t.Fatal("expected an error for an unknown source type")
	}
}

// A source naming no artifact file is a manifest error: there is nothing to turn
// into evidence.
func TestLoadManifestRejectsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	m := writeFile(t, dir, "release.json", `{"sources":[{"type":"sbom","control":"c1"}]}`)
	if _, err := LoadManifest(m); err == nil {
		t.Fatal("expected an error for an empty file reference")
	}
}

// A manifest with no sources cannot gate anything, so it is an error.
func TestLoadManifestRejectsNoSources(t *testing.T) {
	dir := t.TempDir()
	m := writeFile(t, dir, "release.json", `{"release":"x","sources":[]}`)
	if _, err := LoadManifest(m); err == nil {
		t.Fatal("expected an error for a manifest with no sources")
	}
}

// A declared artifact file that cannot be read fails the whole release: missing
// release evidence is a blocked release, not a degraded one.
func TestEvidenceFailsOnMissingArtifact(t *testing.T) {
	dir := t.TempDir()
	manifest := writeFile(t, dir, "release.json", `{
		"sources": [
			{"type":"provenance","file":"/no/such/provenance.json","control":"cfr-part-11-10a-system-validation","expected-builder":"https://github.com/acme/builder"}
		]
	}`)
	m, err := LoadManifest(manifest)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if _, err := m.Evidence(); err == nil {
		t.Fatal("expected Evidence to fail on an unreadable artifact file")
	}
}
