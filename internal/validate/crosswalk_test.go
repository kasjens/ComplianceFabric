package validate

import (
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/crosswalk"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// sectorCatalog defines the target-sector citations a crosswalk maps onto anchor
// controls, alongside the anchor catalog (annex11Catalog) the anchors live in.
func sectorCatalog() oscal.Catalog {
	return oscal.Catalog{
		ID: "dora",
		Controls: []oscal.Control{
			{ID: "dora-9-access", Title: "Access management"},
			{ID: "dora-28-supply-chain", Title: "ICT supply chain"},
		},
	}
}

func TestCrosswalkAnchorResolvesToCatalog(t *testing.T) {
	t.Run("anchor defined in a catalog is not flagged", func(t *testing.T) {
		b := Bundle{
			Catalogs: []oscal.Catalog{annex11Catalog(), sectorCatalog()},
			Crosswalks: []crosswalk.Crosswalk{{Mappings: []crosswalk.Mapping{{
				Control:     "dora-9-access",
				SatisfiedBy: []string{"annex11-12-security"},
			}}}},
		}
		if got := findingsByRule(Run(b), "crosswalk-unresolved-anchor"); len(got) != 0 {
			t.Fatalf("expected no unresolved-anchor findings, got %d: %+v", len(got), got)
		}
	})

	t.Run("anchor not in any catalog is flagged", func(t *testing.T) {
		b := Bundle{
			Catalogs: []oscal.Catalog{annex11Catalog(), sectorCatalog()},
			Crosswalks: []crosswalk.Crosswalk{{Mappings: []crosswalk.Mapping{{
				Control:     "dora-9-access",
				SatisfiedBy: []string{"annex11-typo-control"},
			}}}},
		}
		got := findingsByRule(Run(b), "crosswalk-unresolved-anchor")
		if len(got) != 1 {
			t.Fatalf("expected one unresolved-anchor finding, got %d: %+v", len(got), got)
		}
		if got[0].ControlID != "annex11-typo-control" {
			t.Errorf("finding control id = %q, want annex11-typo-control", got[0].ControlID)
		}
	})
}

func TestCrosswalkTargetResolvesToCatalog(t *testing.T) {
	b := Bundle{
		Catalogs: []oscal.Catalog{annex11Catalog(), sectorCatalog()},
		Crosswalks: []crosswalk.Crosswalk{{Mappings: []crosswalk.Mapping{{
			Control:     "dora-99-nonexistent",
			SatisfiedBy: []string{"annex11-12-security"},
		}}}},
	}
	got := findingsByRule(Run(b), "crosswalk-unresolved-target")
	if len(got) != 1 || got[0].ControlID != "dora-99-nonexistent" {
		t.Fatalf("expected one unresolved-target finding for dora-99-nonexistent, got %+v", got)
	}
}

func TestCrosswalkDuplicateTargetIsFlagged(t *testing.T) {
	b := Bundle{
		Catalogs: []oscal.Catalog{annex11Catalog(), sectorCatalog()},
		Crosswalks: []crosswalk.Crosswalk{{Mappings: []crosswalk.Mapping{
			{Control: "dora-9-access", SatisfiedBy: []string{"annex11-9-audit-trail"}},
			{Control: "dora-9-access", SatisfiedBy: []string{"annex11-12-security"}},
		}}},
	}
	got := findingsByRule(Run(b), "crosswalk-duplicate-target")
	if len(got) != 1 || got[0].ControlID != "dora-9-access" {
		t.Fatalf("expected one duplicate-target finding for dora-9-access, got %+v", got)
	}
}

func TestCrosswalkEmptyMappingIsFlagged(t *testing.T) {
	b := Bundle{
		Catalogs: []oscal.Catalog{annex11Catalog(), sectorCatalog()},
		Crosswalks: []crosswalk.Crosswalk{{Mappings: []crosswalk.Mapping{{
			Control:     "dora-9-access",
			SatisfiedBy: nil,
		}}}},
	}
	got := findingsByRule(Run(b), "crosswalk-empty-mapping")
	if len(got) != 1 || got[0].ControlID != "dora-9-access" {
		t.Fatalf("expected one empty-mapping finding for dora-9-access, got %+v", got)
	}
}

// A well-formed crosswalk over real anchors and targets produces no findings.
func TestValidCrosswalkHasNoFindings(t *testing.T) {
	b := Bundle{
		Catalogs: []oscal.Catalog{annex11Catalog(), sectorCatalog()},
		Crosswalks: []crosswalk.Crosswalk{{Mappings: []crosswalk.Mapping{
			{Control: "dora-9-access", SatisfiedBy: []string{"annex11-12-security"}},
			{Control: "dora-28-supply-chain", SatisfiedBy: []string{"annex11-9-audit-trail"}},
		}}},
	}
	for _, rule := range []string{
		"crosswalk-unresolved-anchor",
		"crosswalk-unresolved-target",
		"crosswalk-duplicate-target",
		"crosswalk-empty-mapping",
	} {
		if got := findingsByRule(Run(b), rule); len(got) != 0 {
			t.Errorf("expected no %s findings, got %d: %+v", rule, len(got), got)
		}
	}
}
