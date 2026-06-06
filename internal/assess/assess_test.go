package assess

import (
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

func bundle() validate.Bundle {
	return validate.Bundle{
		Catalogs: []oscal.Catalog{{
			ID: "annex11",
			Controls: []oscal.Control{
				{ID: "annex11-9-audit-trail", Title: "Audit trail"},
				{ID: "annex11-12-1-access-control", Title: "Access control"},
				{ID: "annex11-5-accuracy-checks", Title: "Accuracy checks"},
			},
		}},
		Profiles: []oscal.Profile{{
			Imports: []oscal.Import{{
				Href: "annex11",
				IncludeControls: []string{
					"annex11-9-audit-trail",
					"annex11-12-1-access-control",
				},
			}},
		}},
		ComponentDefinitions: []oscal.ComponentDefinition{{
			Mappings: []oscal.Mapping{{
				ControlID: "annex11-9-audit-trail",
				ImplementedBy: []oscal.Implementation{
					{Component: "kyverno", PolicyID: "require-audit-logging-annotations"},
				},
			}},
		}},
	}
}

func findingFor(t *testing.T, ar oscal.AssessmentResults, id string) (oscal.AssessmentFinding, bool) {
	t.Helper()
	for _, r := range ar.Results {
		for _, f := range r.Findings {
			if f.ControlID == id {
				return f, true
			}
		}
	}
	return oscal.AssessmentFinding{}, false
}

func TestAssessOnlyCoversSelectedControls(t *testing.T) {
	ar := Assess(bundle())
	if _, ok := findingFor(t, ar, "annex11-5-accuracy-checks"); ok {
		t.Error("unselected control should not appear in assessment findings")
	}
	if len(ar.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(ar.Results))
	}
	if len(ar.Results[0].Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (the selected controls)", len(ar.Results[0].Findings))
	}
}

func TestAssessMarksCoveredControlSatisfied(t *testing.T) {
	f, ok := findingFor(t, Assess(bundle()), "annex11-9-audit-trail")
	if !ok {
		t.Fatal("expected a finding for the covered control")
	}
	if f.Status != oscal.StatusSatisfied {
		t.Errorf("status = %q, want %q", f.Status, oscal.StatusSatisfied)
	}
}

func TestNotSatisfiedReturnsOnlyGaps(t *testing.T) {
	gaps := NotSatisfied(Assess(bundle()))
	if len(gaps) != 1 {
		t.Fatalf("gaps = %d, want 1: %+v", len(gaps), gaps)
	}
	if gaps[0].ControlID != "annex11-12-1-access-control" {
		t.Errorf("gap ControlID = %q, want %q", gaps[0].ControlID, "annex11-12-1-access-control")
	}
}

func TestAssessMarksUncoveredSelectedControlNotSatisfied(t *testing.T) {
	f, ok := findingFor(t, Assess(bundle()), "annex11-12-1-access-control")
	if !ok {
		t.Fatal("expected a finding for the selected-but-unmapped control")
	}
	if f.Status != oscal.StatusNotSatisfied {
		t.Errorf("status = %q, want %q", f.Status, oscal.StatusNotSatisfied)
	}
}
