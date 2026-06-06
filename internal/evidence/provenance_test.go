package evidence

import (
	"testing"
	"time"
)

const trustedBuilder = "https://github.com/kasjens/ComplianceFabric/.github/workflows/release.yml@refs/heads/main"

// slsaStatement is a SLSA v1.0 in-toto provenance statement, the decoded DSSE
// payload from `cosign verify-attestation --type slsaprovenance --output json`.
const slsaStatement = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "registry.example/mes", "digest": { "sha256": "1f2e3d4c5b6a7980" } }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": { "buildType": "https://actions.github.io/buildtypes/workflow/v1" },
    "runDetails": {
      "builder": { "id": "https://github.com/kasjens/ComplianceFabric/.github/workflows/release.yml@refs/heads/main" },
      "metadata": {
        "invocationId": "https://github.com/kasjens/ComplianceFabric/actions/runs/42",
        "startedOn": "2026-06-06T10:00:00Z",
        "finishedOn": "2026-06-06T10:05:00Z"
      }
    }
  }
}`

func TestFromProvenanceTrustedBuilderSatisfied(t *testing.T) {
	records, err := FromProvenance([]byte(slsaStatement), trustedBuilder, "cfr-part-11-10a-system-validation")
	if err != nil {
		t.Fatalf("FromProvenance: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(records), records)
	}
	r := records[0]
	if r.ControlID != "cfr-part-11-10a-system-validation" {
		t.Errorf("control id = %q", r.ControlID)
	}
	if r.Result != "satisfied" {
		t.Errorf("result = %q, want satisfied (provenance from the trusted builder)", r.Result)
	}
	if r.Subject != "image/registry.example/mes@sha256:1f2e3d4c5b6a7980" {
		t.Errorf("subject = %q", r.Subject)
	}
	if r.Source != "slsa-provenance" {
		t.Errorf("source = %q", r.Source)
	}
	want := time.Date(2026, 6, 6, 10, 5, 0, 0, time.UTC)
	if !r.ObservedAt.Equal(want) {
		t.Errorf("observed-at = %v, want %v (build finished time)", r.ObservedAt, want)
	}
}

func TestFromProvenanceUntrustedBuilderNotSatisfied(t *testing.T) {
	records, err := FromProvenance([]byte(slsaStatement), "https://evil.example/builder", "cfr-part-11-10a-system-validation")
	if err != nil {
		t.Fatalf("FromProvenance: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	if records[0].Result != "not-satisfied" {
		t.Errorf("result = %q, want not-satisfied (builder is not the trusted one)", records[0].Result)
	}
}

func TestFromProvenanceWrongPredicateTypeNotSatisfied(t *testing.T) {
	// An attestation that is not SLSA provenance (e.g. an SBOM) does not evidence
	// build provenance, even if the builder would match.
	notProvenance := `{
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [{ "name": "registry.example/mes", "digest": { "sha256": "1f2e3d4c5b6a7980" } }],
      "predicateType": "https://spdx.dev/Document",
      "predicate": { "runDetails": { "builder": { "id": "` + trustedBuilder + `" } } }
    }`
	records, err := FromProvenance([]byte(notProvenance), trustedBuilder, "cfr-part-11-10a-system-validation")
	if err != nil {
		t.Fatalf("FromProvenance: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	if records[0].Result != "not-satisfied" {
		t.Errorf("result = %q, want not-satisfied (not a SLSA provenance attestation)", records[0].Result)
	}
}

func TestFromProvenanceFanOutToSubjects(t *testing.T) {
	multi := `{
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        { "name": "registry.example/mes", "digest": { "sha256": "aaaa" } },
        { "name": "registry.example/sidecar", "digest": { "sha256": "bbbb" } }
      ],
      "predicateType": "https://slsa.dev/provenance/v1",
      "predicate": { "runDetails": { "builder": { "id": "` + trustedBuilder + `" },
        "metadata": { "finishedOn": "2026-06-06T10:05:00Z" } } }
    }`
	records, err := FromProvenance([]byte(multi), trustedBuilder, "cfr-part-11-10a-system-validation")
	if err != nil {
		t.Fatalf("FromProvenance: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("want one record per subject, got %d", len(records))
	}
	if records[0].Subject != "image/registry.example/mes@sha256:aaaa" ||
		records[1].Subject != "image/registry.example/sidecar@sha256:bbbb" {
		t.Errorf("subjects = %q, %q", records[0].Subject, records[1].Subject)
	}
}
