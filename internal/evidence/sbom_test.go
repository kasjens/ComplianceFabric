package evidence

import (
	"testing"
	"time"
)

// cycloneDXSBOM is a CycloneDX JSON SBOM as syft emits it (`syft <image> -o
// cyclonedx-json`): a metadata.component naming the inventoried image and a
// components list of what is inside it.
const cycloneDXSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "timestamp": "2026-06-06T10:00:00Z",
    "component": { "type": "container", "name": "registry.example/mes", "version": "1.4.2" }
  },
  "components": [
    { "type": "library", "name": "openssl", "version": "3.0.8" },
    { "type": "library", "name": "zlib", "version": "1.2.13" }
  ]
}`

func TestFromSBOMCleanInventoryIsSatisfied(t *testing.T) {
	policy := SBOMPolicy{Banned: []BannedComponent{{Name: "log4j", Version: "2.14.1"}}}
	records, err := FromSBOM([]byte(cycloneDXSBOM), policy, "cfr-part-11-10a-system-validation")
	if err != nil {
		t.Fatalf("FromSBOM: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(records), records)
	}
	r := records[0]
	if r.Result != "satisfied" {
		t.Errorf("result = %q, want satisfied (no banned component present)", r.Result)
	}
	if r.ControlID != "cfr-part-11-10a-system-validation" {
		t.Errorf("control id = %q", r.ControlID)
	}
	if r.Subject != "image/registry.example/mes@1.4.2" {
		t.Errorf("subject = %q", r.Subject)
	}
	if r.Source != "sbom-content" {
		t.Errorf("source = %q", r.Source)
	}
	want := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	if !r.ObservedAt.Equal(want) {
		t.Errorf("observed-at = %v, want %v (SBOM timestamp)", r.ObservedAt, want)
	}
}

func TestFromSBOMBannedComponentIsNotSatisfied(t *testing.T) {
	policy := SBOMPolicy{Banned: []BannedComponent{{Name: "openssl", Version: "3.0.8"}}}
	records, err := FromSBOM([]byte(cycloneDXSBOM), policy, "cfr-part-11-10a-system-validation")
	if err != nil {
		t.Fatalf("FromSBOM: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record (the violation), got %d: %+v", len(records), records)
	}
	r := records[0]
	if r.Result != "not-satisfied" {
		t.Errorf("result = %q, want not-satisfied (banned component present)", r.Result)
	}
	if r.Subject != "component/openssl@3.0.8" {
		t.Errorf("subject = %q, want the banned component", r.Subject)
	}
}

func TestFromSBOMBannedByNameMatchesAnyVersion(t *testing.T) {
	// An empty Version bans the component at every version.
	policy := SBOMPolicy{Banned: []BannedComponent{{Name: "zlib"}}}
	records, err := FromSBOM([]byte(cycloneDXSBOM), policy, "c")
	if err != nil {
		t.Fatalf("FromSBOM: %v", err)
	}
	if len(records) != 1 || records[0].Result != "not-satisfied" {
		t.Fatalf("want one not-satisfied record, got %+v", records)
	}
	if records[0].Subject != "component/zlib@1.2.13" {
		t.Errorf("subject = %q", records[0].Subject)
	}
}

func TestFromSBOMBannedVersionMismatchIsSatisfied(t *testing.T) {
	// A different version of the same name is not the banned artifact.
	policy := SBOMPolicy{Banned: []BannedComponent{{Name: "openssl", Version: "1.0.0"}}}
	records, err := FromSBOM([]byte(cycloneDXSBOM), policy, "c")
	if err != nil {
		t.Fatalf("FromSBOM: %v", err)
	}
	if len(records) != 1 || records[0].Result != "satisfied" {
		t.Fatalf("want one satisfied record, got %+v", records)
	}
}

func TestFromSBOMFanOutToEveryViolation(t *testing.T) {
	policy := SBOMPolicy{Banned: []BannedComponent{
		{Name: "openssl", Version: "3.0.8"},
		{Name: "zlib"},
	}}
	records, err := FromSBOM([]byte(cycloneDXSBOM), policy, "c")
	if err != nil {
		t.Fatalf("FromSBOM: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("want one record per violation, got %d: %+v", len(records), records)
	}
	for _, r := range records {
		if r.Result != "not-satisfied" {
			t.Errorf("record %q result = %q, want not-satisfied", r.Subject, r.Result)
		}
	}
}

func TestFromSBOMEmptyInventoryIsNotSatisfied(t *testing.T) {
	// An SBOM that inventories nothing is not evidence of what is inside the
	// image, so it cannot satisfy the control.
	empty := `{
      "bomFormat": "CycloneDX",
      "metadata": {
        "timestamp": "2026-06-06T10:00:00Z",
        "component": { "name": "registry.example/mes", "version": "1.4.2" }
      },
      "components": []
    }`
	records, err := FromSBOM([]byte(empty), SBOMPolicy{}, "c")
	if err != nil {
		t.Fatalf("FromSBOM: %v", err)
	}
	if len(records) != 1 || records[0].Result != "not-satisfied" {
		t.Fatalf("want one not-satisfied record for an empty inventory, got %+v", records)
	}
	if records[0].Subject != "image/registry.example/mes@1.4.2" {
		t.Errorf("subject = %q", records[0].Subject)
	}
}

// When the SBOM's image component carries a digest (syft puts it in the purl for
// a container image), the image-level record references that artifact by digest.
func TestFromSBOMImageRecordCarriesArtifactDigest(t *testing.T) {
	withDigest := `{
      "bomFormat": "CycloneDX",
      "metadata": {
        "timestamp": "2026-06-06T10:00:00Z",
        "component": {
          "type": "container",
          "name": "registry.example/mes",
          "version": "1.4.2",
          "purl": "pkg:oci/mes@sha256:1f2e3d4c5b6a7980?repository_url=registry.example/mes"
        }
      },
      "components": [ { "type": "library", "name": "openssl", "version": "3.0.8" } ]
    }`
	records, err := FromSBOM([]byte(withDigest), SBOMPolicy{}, "c")
	if err != nil {
		t.Fatalf("FromSBOM: %v", err)
	}
	if len(records) != 1 || records[0].Result != "satisfied" {
		t.Fatalf("want one satisfied image record, got %+v", records)
	}
	if records[0].ArtifactRef != "sha256:1f2e3d4c5b6a7980" {
		t.Errorf("artifact-ref = %q, want sha256:1f2e3d4c5b6a7980", records[0].ArtifactRef)
	}
}

func TestFromSBOMMalformedJSONIsError(t *testing.T) {
	if _, err := FromSBOM([]byte(`{not json`), SBOMPolicy{}, "c"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
