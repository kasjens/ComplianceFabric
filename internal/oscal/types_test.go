package oscal

import "testing"

// A component carries rule definitions as rule_set props, and each
// implemented-requirement references rules by Rule_Id. ControlPolicies resolves
// that indirection down to the concrete (control, component, check) triples the
// rest of the engine enforces against.
func sampleComponent() Component {
	return Component{
		Title: "kyverno",
		Type:  "validation",
		Props: []Prop{
			{Name: "Rule_Id", Value: "least-privilege-rbac", Remarks: "rule_set_00"},
			{Name: "Check_Id", Value: "disallow-cluster-admin-binding", Remarks: "rule_set_00"},
			{Name: "Rule_Id", Value: "run-as-non-root", Remarks: "rule_set_01"},
			{Name: "Check_Id", Value: "require-run-as-non-root", Remarks: "rule_set_01"},
		},
		ControlImplementations: []ControlImplementation{{
			Source: "controls/profiles/pharma-mes-baseline.json",
			ImplementedRequirements: []ImplementedRequirement{{
				ControlID: "annex11-12-1-access-control",
				Props: []Prop{
					{Name: "Rule_Id", Value: "least-privilege-rbac"},
					{Name: "Rule_Id", Value: "run-as-non-root"},
				},
			}},
		}},
	}
}

func TestControlPoliciesResolvesRuleIdToCheckId(t *testing.T) {
	cd := ComponentDefinition{Components: []Component{sampleComponent()}}
	got := cd.ControlPolicies()
	want := []ControlPolicy{
		{ControlID: "annex11-12-1-access-control", Component: "kyverno", PolicyID: "disallow-cluster-admin-binding"},
		{ControlID: "annex11-12-1-access-control", Component: "kyverno", PolicyID: "require-run-as-non-root"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d policies %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("policy[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestControlPoliciesFlagsRuleIdWithNoCheck(t *testing.T) {
	cd := ComponentDefinition{Components: []Component{{
		Title: "kyverno",
		Props: []Prop{{Name: "Rule_Id", Value: "orphan-rule", Remarks: "rule_set_00"}},
		ControlImplementations: []ControlImplementation{{
			ImplementedRequirements: []ImplementedRequirement{{
				ControlID: "c1",
				Props:     []Prop{{Name: "Rule_Id", Value: "orphan-rule"}},
			}},
		}},
	}}}
	// A rule set without a Check_Id yields a triple with an empty PolicyID so
	// validation can flag it rather than silently dropping the requirement.
	got := cd.ControlPolicies()
	if len(got) != 1 || got[0].PolicyID != "" {
		t.Fatalf("expected one triple with empty PolicyID, got %+v", got)
	}
}

func TestControlPoliciesFlagsUnknownRuleReference(t *testing.T) {
	cd := ComponentDefinition{Components: []Component{{
		Title: "kyverno",
		ControlImplementations: []ControlImplementation{{
			ImplementedRequirements: []ImplementedRequirement{{
				ControlID: "c1",
				Props:     []Prop{{Name: "Rule_Id", Value: "does-not-exist"}},
			}},
		}},
	}}}
	got := cd.UnresolvedRules()
	if len(got) != 1 || got[0].RuleID != "does-not-exist" || got[0].ControlID != "c1" {
		t.Fatalf("expected one unresolved rule ref for c1/does-not-exist, got %+v", got)
	}
}
