package assess

import (
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/report"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

// REPRODUCTION — Workstream R.2, plan item 2.1. Expected to FAIL against cac9f78.

// bundleWithRuleButNoCheck builds a bundle whose single selected control maps to
// a Rule_Id that is declared on the component but has NO Check_Id in its rule-set
// group. oscal.ruleChecks resolves that rule to "" and ControlPolicies documents
// the result: "references to a known rule with no Check_Id produce a triple with
// an empty PolicyID ... so callers can flag it".
//
// report.Coverage does not flag it — it appends the "" straight into PolicyIDs.
// assess then passes on len(PolicyIDs) > 0, so the control reports satisfied with
// zero enforcement in existence.
func bundleWithRuleButNoCheck() validate.Bundle {
	const control = "annex11-10-change-control"

	return validate.Bundle{
		Catalogs: []oscal.Catalog{{
			ID:       "annex11",
			Controls: []oscal.Control{{ID: control, Title: "Change control"}},
		}},
		Profiles: []oscal.Profile{{
			Imports: []oscal.Import{{Href: "annex11", IncludeControls: []string{control}}},
		}},
		ComponentDefinitions: []oscal.ComponentDefinition{{
			Components: []oscal.Component{{
				Title: "Kyverno",
				Props: []oscal.Prop{
					// Rule declared, but the group carries no Check_Id prop.
					{Name: "Rule_Id", Value: "rule-1", Remarks: "rule_set_00"},
					{Name: "Rule_Description", Value: "changes are reviewed", Remarks: "rule_set_00"},
				},
				ControlImplementations: []oscal.ControlImplementation{{
					Source: "annex11",
					ImplementedRequirements: []oscal.ImplementedRequirement{{
						ControlID: control,
						Props:     []oscal.Prop{{Name: "Rule_Id", Value: "rule-1"}},
					}},
				}},
			}},
		}},
	}
}

// The empty policy id must not be counted as coverage.
func TestRepro21CoverageMustNotCountEmptyPolicyID(t *testing.T) {
	rows := report.Coverage(bundleWithRuleButNoCheck())
	if len(rows) != 1 {
		t.Fatalf("expected 1 coverage row, got %d", len(rows))
	}
	for _, id := range rows[0].PolicyIDs {
		if id == "" {
			t.Fatalf("Coverage reported an empty policy id as enforcement for %s: %q; "+
				"a rule with no Check_Id is not coverage", rows[0].ControlID, rows[0].PolicyIDs)
		}
	}
}

// The user-visible consequence: `fabric assess --strict` calls this control
// satisfied, so a control with no enforcement behind it passes the gate.
func TestRepro21AssessMustNotSatisfyRuleWithNoCheck(t *testing.T) {
	res := Assess(bundleWithRuleButNoCheck())
	if len(res.Results) != 1 || len(res.Results[0].Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %+v", res.Results)
	}

	f := res.Results[0].Findings[0]
	if f.Status != oscal.StatusNotSatisfied {
		t.Errorf("control %s with a Rule_Id but no Check_Id assessed as %q, want %q — "+
			"there is zero enforcement behind it", f.ControlID, f.Status, oscal.StatusNotSatisfied)
	}
}
