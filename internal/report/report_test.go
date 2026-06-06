package report

import (
	"strings"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

func sampleBundle() validate.Bundle {
	return validate.Bundle{
		Catalogs: []oscal.Catalog{{
			ID: "annex11",
			Controls: []oscal.Control{
				{ID: "annex11-9-audit-trail", Title: "Audit trail"},
				{ID: "annex11-5-accuracy-checks", Title: "Accuracy checks"},
			},
		}},
		Profiles: []oscal.Profile{{
			Imports: []oscal.Import{{
				Href:            "annex11",
				IncludeControls: []string{"annex11-9-audit-trail"},
			}},
		}},
		ComponentDefinitions: []oscal.ComponentDefinition{{
			Components: []oscal.Component{
				{
					Title: "kyverno",
					Props: []oscal.Prop{
						{Name: "Rule_Id", Value: "audit-logging-annotation", Remarks: "rule_set_00"},
						{Name: "Check_Id", Value: "require-audit-logging-annotations", Remarks: "rule_set_00"},
					},
					ControlImplementations: []oscal.ControlImplementation{{
						ImplementedRequirements: []oscal.ImplementedRequirement{{
							ControlID: "annex11-9-audit-trail",
							Props:     []oscal.Prop{{Name: "Rule_Id", Value: "audit-logging-annotation"}},
						}},
					}},
				},
				{
					Title: "evidence-ledger",
					Props: []oscal.Prop{
						{Name: "Rule_Id", Value: "append-only-evidence", Remarks: "rule_set_00"},
						{Name: "Check_Id", Value: "append-only-storage", Remarks: "rule_set_00"},
					},
					ControlImplementations: []oscal.ControlImplementation{{
						ImplementedRequirements: []oscal.ImplementedRequirement{{
							ControlID: "annex11-9-audit-trail",
							Props:     []oscal.Prop{{Name: "Rule_Id", Value: "append-only-evidence"}},
						}},
					}},
				},
			},
		}},
	}
}

func find(t *testing.T, cov []ControlCoverage, id string) ControlCoverage {
	t.Helper()
	for _, c := range cov {
		if c.ControlID == id {
			return c
		}
	}
	t.Fatalf("control %q not present in coverage", id)
	return ControlCoverage{}
}

func TestCoverageRetainsEveryCatalogControl(t *testing.T) {
	cov := Coverage(sampleBundle())
	if len(cov) != 2 {
		t.Fatalf("coverage rows = %d, want 2", len(cov))
	}
}

func TestCoverageMarksSelectedAndMappedControl(t *testing.T) {
	c := find(t, Coverage(sampleBundle()), "annex11-9-audit-trail")
	if !c.Selected {
		t.Error("audit-trail control should be marked Selected")
	}
	if c.CatalogID != "annex11" {
		t.Errorf("CatalogID = %q, want annex11", c.CatalogID)
	}
	want := []string{"require-audit-logging-annotations", "append-only-storage"}
	if len(c.PolicyIDs) != len(want) {
		t.Fatalf("PolicyIDs = %v, want %v", c.PolicyIDs, want)
	}
	for i := range want {
		if c.PolicyIDs[i] != want[i] {
			t.Errorf("PolicyIDs[%d] = %q, want %q", i, c.PolicyIDs[i], want[i])
		}
	}
}

func TestRenderShowsControlsAndSummary(t *testing.T) {
	out := Render(Coverage(sampleBundle()))

	for _, want := range []string{
		"annex11-9-audit-trail",
		"require-audit-logging-annotations",
		"annex11-5-accuracy-checks",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q. output:\n%s", want, out)
		}
	}

	if !strings.Contains(out, "2 controls") || !strings.Contains(out, "1 selected") {
		t.Errorf("render missing expected summary. output:\n%s", out)
	}
}

func TestCoverageMarksUnselectedUnmappedControl(t *testing.T) {
	c := find(t, Coverage(sampleBundle()), "annex11-5-accuracy-checks")
	if c.Selected {
		t.Error("accuracy-checks control should not be Selected")
	}
	if len(c.PolicyIDs) != 0 {
		t.Errorf("PolicyIDs = %v, want empty", c.PolicyIDs)
	}
}
