package oscal

import (
	"testing"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

// ruleChecks builds map[Rule_Id]Check_Id by iterating the groupRule MAP. When two
// rule-set groups declare the SAME Rule_Id with different Check_Ids, which one
// wins depends on Go's randomised map iteration order. So `fabric generate`
// composes a DIFFERENT policy set from byte-identical inputs — the compliance
// artefact is not reproducible, which is the property an auditor relies on.
func TestDuplicateRuleIDMustNotBeNondeterministic(t *testing.T) {
	cd := ComponentDefinition{
		Components: []Component{{
			Title: "Kyverno",
			Props: []Prop{
				{Name: "Rule_Id", Value: "rule-1", Remarks: "rule_set_00"},
				{Name: "Check_Id", Value: "check-alpha", Remarks: "rule_set_00"},
				// Same Rule_Id declared again in a second group, different check.
				{Name: "Rule_Id", Value: "rule-1", Remarks: "rule_set_01"},
				{Name: "Check_Id", Value: "check-beta", Remarks: "rule_set_01"},
			},
			ControlImplementations: []ControlImplementation{{
				Source: "annex11",
				ImplementedRequirements: []ImplementedRequirement{{
					ControlID: "annex11-10-change-control",
					Props:     []Prop{{Name: "Rule_Id", Value: "rule-1"}},
				}},
			}},
		}},
	}

	seen := map[string]int{}
	for i := 0; i < 500; i++ {
		policies := cd.ControlPolicies()
		if len(policies) != 1 {
			t.Fatalf("expected 1 resolved policy, got %d", len(policies))
		}
		seen[policies[0].PolicyID]++
	}

	if len(seen) > 1 {
		t.Errorf("a duplicate Rule_Id resolved to %d different checks across identical "+
			"runs (%v); `fabric generate` is not reproducible from identical inputs. "+
			"A duplicate Rule_Id must be rejected outright.", len(seen), seen)
	}
}
