package validate

import (
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

func annex11Catalog() oscal.Catalog {
	return oscal.Catalog{
		ID: "annex11",
		Controls: []oscal.Control{
			{ID: "annex11-9-audit-trail", Title: "Audit trail"},
			{ID: "annex11-12-security", Title: "Security"},
		},
	}
}

func findingsByRule(fs []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func componentDef(controlID string) oscal.ComponentDefinition {
	return oscal.ComponentDefinition{
		Components: []oscal.Component{{
			Title: "platform-logging",
			Props: []oscal.Prop{
				{Name: "Rule_Id", Value: "audit-logging", Remarks: "rule_set_00"},
				{Name: "Check_Id", Value: "require-audit-logging", Remarks: "rule_set_00"},
			},
			ControlImplementations: []oscal.ControlImplementation{{
				Source: "annex11",
				ImplementedRequirements: []oscal.ImplementedRequirement{{
					ControlID: controlID,
					Props:     []oscal.Prop{{Name: "Rule_Id", Value: "audit-logging"}},
				}},
			}},
		}},
	}
}

func TestMappingControlResolvesToCatalog(t *testing.T) {
	t.Run("mapping to a known control is not flagged", func(t *testing.T) {
		b := Bundle{
			Catalogs:             []oscal.Catalog{annex11Catalog()},
			ComponentDefinitions: []oscal.ComponentDefinition{componentDef("annex11-9-audit-trail")},
		}
		if got := findingsByRule(Run(b), "unmapped-control"); len(got) != 0 {
			t.Fatalf("expected no unmapped-control findings, got %d: %+v", len(got), got)
		}
	})

	t.Run("mapping to an unknown control is flagged", func(t *testing.T) {
		b := Bundle{
			Catalogs:             []oscal.Catalog{annex11Catalog()},
			ComponentDefinitions: []oscal.ComponentDefinition{componentDef("annex11-99-ghost")},
		}
		got := findingsByRule(Run(b), "unmapped-control")
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 unmapped-control finding, got %d: %+v", len(got), got)
		}
		if got[0].ControlID != "annex11-99-ghost" {
			t.Errorf("finding ControlID = %q, want %q", got[0].ControlID, "annex11-99-ghost")
		}
	})
}

func TestCatalogHasNoDuplicateControlIDs(t *testing.T) {
	t.Run("unique control IDs are not flagged", func(t *testing.T) {
		b := Bundle{Catalogs: []oscal.Catalog{annex11Catalog()}}
		if got := findingsByRule(Run(b), "duplicate-control-id"); len(got) != 0 {
			t.Fatalf("expected no duplicate-control-id findings, got %d: %+v", len(got), got)
		}
	})

	t.Run("a repeated control ID is flagged once", func(t *testing.T) {
		cat := annex11Catalog()
		cat.Controls = append(cat.Controls, oscal.Control{ID: "annex11-9-audit-trail", Title: "Dup"})
		b := Bundle{Catalogs: []oscal.Catalog{cat}}
		got := findingsByRule(Run(b), "duplicate-control-id")
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 duplicate-control-id finding, got %d: %+v", len(got), got)
		}
		if got[0].ControlID != "annex11-9-audit-trail" {
			t.Errorf("finding ControlID = %q, want %q", got[0].ControlID, "annex11-9-audit-trail")
		}
	})
}

func TestProfileControlCoverage(t *testing.T) {
	t.Run("a selected control with a mapping is covered", func(t *testing.T) {
		b := Bundle{
			Catalogs: []oscal.Catalog{annex11Catalog()},
			Profiles: []oscal.Profile{{Imports: []oscal.Import{{
				Href: "annex11", IncludeControls: []string{"annex11-9-audit-trail"},
			}}}},
			ComponentDefinitions: []oscal.ComponentDefinition{componentDef("annex11-9-audit-trail")},
		}
		if got := findingsByRule(Run(b), "uncovered-control"); len(got) != 0 {
			t.Fatalf("expected no uncovered-control findings, got %d: %+v", len(got), got)
		}
	})

	t.Run("a selected control with no mapping is flagged", func(t *testing.T) {
		b := Bundle{
			Catalogs: []oscal.Catalog{annex11Catalog()},
			Profiles: []oscal.Profile{{Imports: []oscal.Import{{
				Href: "annex11", IncludeControls: []string{"annex11-12-security"},
			}}}},
			ComponentDefinitions: []oscal.ComponentDefinition{componentDef("annex11-9-audit-trail")},
		}
		got := findingsByRule(Run(b), "uncovered-control")
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 uncovered-control finding, got %d: %+v", len(got), got)
		}
		if got[0].ControlID != "annex11-12-security" {
			t.Errorf("finding ControlID = %q, want %q", got[0].ControlID, "annex11-12-security")
		}
	})
}

func TestRuleReferencesResolve(t *testing.T) {
	t.Run("a requirement referencing an undefined rule is flagged", func(t *testing.T) {
		b := Bundle{
			Catalogs: []oscal.Catalog{annex11Catalog()},
			ComponentDefinitions: []oscal.ComponentDefinition{{Components: []oscal.Component{{
				Title: "platform-logging",
				ControlImplementations: []oscal.ControlImplementation{{
					ImplementedRequirements: []oscal.ImplementedRequirement{{
						ControlID: "annex11-9-audit-trail",
						Props:     []oscal.Prop{{Name: "Rule_Id", Value: "ghost-rule"}},
					}},
				}},
			}}}},
		}
		got := findingsByRule(Run(b), "unresolved-rule")
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 unresolved-rule finding, got %d: %+v", len(got), got)
		}
		if got[0].ControlID != "annex11-9-audit-trail" {
			t.Errorf("finding ControlID = %q, want %q", got[0].ControlID, "annex11-9-audit-trail")
		}
	})

	t.Run("a rule set without a check is flagged", func(t *testing.T) {
		b := Bundle{
			Catalogs: []oscal.Catalog{annex11Catalog()},
			ComponentDefinitions: []oscal.ComponentDefinition{{Components: []oscal.Component{{
				Title: "platform-logging",
				Props: []oscal.Prop{{Name: "Rule_Id", Value: "audit-logging", Remarks: "rule_set_00"}},
				ControlImplementations: []oscal.ControlImplementation{{
					ImplementedRequirements: []oscal.ImplementedRequirement{{
						ControlID: "annex11-9-audit-trail",
						Props:     []oscal.Prop{{Name: "Rule_Id", Value: "audit-logging"}},
					}},
				}},
			}}}},
		}
		if got := findingsByRule(Run(b), "rule-missing-check"); len(got) != 1 {
			t.Fatalf("expected exactly 1 rule-missing-check finding, got %d: %+v", len(got), got)
		}
	})
}

func TestProfileControlResolvesToCatalog(t *testing.T) {
	t.Run("valid profile produces no unresolved-control findings", func(t *testing.T) {
		b := Bundle{
			Catalogs: []oscal.Catalog{annex11Catalog()},
			Profiles: []oscal.Profile{{
				Imports: []oscal.Import{{
					Href:            "annex11",
					IncludeControls: []string{"annex11-9-audit-trail"},
				}},
			}},
		}

		got := findingsByRule(Run(b), "unresolved-control")
		if len(got) != 0 {
			t.Fatalf("expected no unresolved-control findings, got %d: %+v", len(got), got)
		}
	})

	t.Run("profile selecting an unknown control is flagged", func(t *testing.T) {
		b := Bundle{
			Catalogs: []oscal.Catalog{annex11Catalog()},
			Profiles: []oscal.Profile{{
				Imports: []oscal.Import{{
					Href:            "annex11",
					IncludeControls: []string{"annex11-99-does-not-exist"},
				}},
			}},
		}

		got := findingsByRule(Run(b), "unresolved-control")
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 unresolved-control finding, got %d: %+v", len(got), got)
		}
		if got[0].ControlID != "annex11-99-does-not-exist" {
			t.Errorf("finding ControlID = %q, want %q", got[0].ControlID, "annex11-99-does-not-exist")
		}
	})
}
