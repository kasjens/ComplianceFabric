package crosswalk

import (
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// REPRODUCTION — Workstream R.2, plan item 2.2. Expected to FAIL against cac9f78.

// Apply seeds result := StatusSatisfied before the anchor loop, so a mapping with
// zero anchors never enters the loop and is emitted satisfied. A crosswalk whose
// "satisfied-by" is empty — or whose key was misspelled, so it decodes to nil —
// therefore claims a second-framework citation is met with no evidence at all.
func TestRepro22EmptyAnchorSetMustNotSatisfy(t *testing.T) {
	cases := []struct {
		name string
		cw   Crosswalk
	}{
		{
			name: "explicit empty satisfied-by",
			cw:   Crosswalk{Mappings: []Mapping{{Control: "DORA-9.1", SatisfiedBy: []string{}}}},
		},
		{
			name: "misspelled key decodes to nil",
			cw:   Crosswalk{Mappings: []Mapping{{Control: "DORA-9.1", SatisfiedBy: nil}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			derived := Apply(nil, tc.cw)
			if len(derived) != 1 {
				t.Fatalf("expected 1 derived record, got %d", len(derived))
			}
			if got := derived[0].Result; got != oscal.StatusNotSatisfied {
				t.Errorf("mapping with zero anchors emitted %q for %s; a citation backed by "+
					"no anchors must never be satisfied by vacuity", got, tc.cw.Mappings[0].Control)
			}
			if derived[0].ObservedAt.IsZero() && derived[0].Result == oscal.StatusSatisfied {
				t.Errorf("satisfied record carries a zero observed-at, so it is satisfied " +
					"as of no point in time")
			}
		})
	}
}

// An unknown anchor id (nothing in the evidence set answers it) must also be
// not-satisfied rather than silently ignored.
func TestRepro22UnknownAnchorMustNotSatisfy(t *testing.T) {
	records := []evidence.Record{}
	cw := Crosswalk{Mappings: []Mapping{{Control: "DORA-9.1", SatisfiedBy: []string{"no-such-control"}}}}

	derived := Apply(records, cw)
	if len(derived) != 1 {
		t.Fatalf("expected 1 derived record, got %d", len(derived))
	}
	if got := derived[0].Result; got != oscal.StatusNotSatisfied {
		t.Errorf("unknown anchor emitted %q, want %q", got, oscal.StatusNotSatisfied)
	}
}
