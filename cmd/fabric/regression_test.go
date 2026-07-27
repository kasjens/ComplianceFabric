package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

// LoadManifest deliberately guards against a manifest with NO SOURCES, because
// that "would otherwise clear the gate by vacuity". It does not guard the same
// vacuity one level down: a source that is present and readable but whose producer
// yields NO RECORDS. FromProvenance returns (nil, nil) for an attestation with an
// empty subject, so the release gate sees zero records, finds nothing
// unsatisfied, and clears the release.
func TestReleaseGateMustBlockOnZeroEvidence(t *testing.T) {
	dir := t.TempDir()

	// A syntactically valid in-toto statement from the expected builder, but with
	// an empty subject — nothing is actually attested.
	att := filepath.Join(dir, "provenance.json")
	builder := "https://github.com/kasjens/ComplianceFabric/.github/workflows/release.yml@refs/heads/main"
	writeFixture(t, att, `{
	  "_type": "https://in-toto.io/Statement/v1",
	  "subject": [],
	  "predicateType": "https://slsa.dev/provenance/v1",
	  "predicate": { "runDetails": { "builder": { "id": "`+builder+`" },
	    "metadata": { "finishedOn": "2026-06-06T10:05:00Z" } } }
	}`)

	manifest := filepath.Join(dir, "release.json")
	writeFixture(t, manifest, `{"release":"mes-1.4.2","sources":[
	  {"type":"provenance","file":"`+filepath.ToSlash(att)+`","control":"cfr-part-11-10a-system-validation","expected-builder":"`+builder+`"}
	]}`)

	led := filepath.Join(dir, "release.ledger")

	var out bytes.Buffer
	code := run([]string{"release-gate", manifest, "--ledger", led}, &out)

	if code == 0 {
		t.Fatalf("release-gate cleared a release backed by ZERO evidence records "+
			"(exit 0). Absence of evidence is not evidence of compliance.\noutput: %s",
			strings.TrimSpace(out.String()))
	}
}
