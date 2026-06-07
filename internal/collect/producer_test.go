package collect

import (
	"sort"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// Run must reject an unknown source type loudly: a typo in a source config should
// fail rather than silently collect nothing.
func TestRunUnknownTypeIsError(t *testing.T) {
	if _, err := Run("not-a-producer", []byte(`{}`), Params{}); err == nil {
		t.Fatal("expected an error for an unknown source type")
	}
}

// Every evidence source the CLI exposes as a producing subcommand must be
// registered under the same token, so a source config and a command name refer to
// the same producer. This is the "one definition" guarantee the registry exists
// to provide.
func TestProducersCoverEveryKnownSource(t *testing.T) {
	want := []string{"change-control", "drift", "eval-gate", "policy-report", "provenance", "sbom", "trace"}
	var got []string
	for name := range Producers {
		got = append(got, name)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("registered producers %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("registered producers %v, want %v", got, want)
		}
	}
}

// Run must plumb Params.ControlID into a producer that keys records to a control.
func TestRunChangeControlUsesControlID(t *testing.T) {
	pr := `{"number":7,"state":"MERGED","author":{"login":"dev"},"mergedAt":"2026-01-02T03:04:05Z","mergeCommit":{"oid":"abc123"},"reviews":[{"author":{"login":"rev"},"state":"APPROVED"}]}`
	records, err := Run("change-control", []byte(pr), Params{ControlID: "annex11-10-change-control"})
	if err != nil {
		t.Fatalf("Run change-control: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].ControlID != "annex11-10-change-control" {
		t.Errorf("control id not plumbed through: got %q", records[0].ControlID)
	}
	if records[0].Result != oscal.StatusSatisfied {
		t.Errorf("a merged, approved PR should be satisfied, got %q", records[0].Result)
	}
}

// Run must plumb Params.SBOMPolicy into the sbom producer.
func TestRunSBOMUsesPolicy(t *testing.T) {
	sbom := `{"metadata":{"timestamp":"2026-01-02T03:04:05Z","component":{"name":"img","version":"1"}},"components":[{"name":"log4j-core","version":"2.14.0"}]}`
	params := Params{
		ControlID:  "cfr-part-11-10a-system-validation",
		SBOMPolicy: evidence.SBOMPolicy{Banned: []evidence.BannedComponent{{Name: "log4j-core"}}},
	}
	records, err := Run("sbom", []byte(sbom), params)
	if err != nil {
		t.Fatalf("Run sbom: %v", err)
	}
	if len(records) != 1 || records[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("expected one not-satisfied record for the banned component, got %v", records)
	}
}

// Run must plumb Params.Registry into the trace producer.
func TestRunTraceUsesRegistry(t *testing.T) {
	reg := registry.Registry{Agents: []registry.Agent{{
		ID: "release-reviewer", Version: "1.0.0", Owner: "q@example.com",
		Prompts: []string{"change-control-review"}, Tools: []string{"gh-pr-read"},
	}}}
	log := `{"id":"i1","agent":"release-reviewer","prompt":"change-control-review","tools":["gh-pr-read"],"timestamp":"2026-01-02T03:04:05Z","allowed":true}`
	records, err := Run("trace", []byte(log), Params{ControlID: "eu-ai-act-12-record-keeping", Registry: reg})
	if err != nil {
		t.Fatalf("Run trace: %v", err)
	}
	if len(records) != 1 || records[0].Result != oscal.StatusSatisfied {
		t.Fatalf("expected one satisfied trace record, got %v", records)
	}
}
