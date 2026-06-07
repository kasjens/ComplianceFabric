package crosswalk

import (
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

func rec(control, result string, at time.Time) evidence.Record {
	return evidence.Record{
		ControlID:  control,
		Subject:    "subject/" + control,
		Result:     result,
		ObservedAt: at,
		Source:     "test",
	}
}

func TestApplyRollsSatisfiedAnchorUpToTargetCitation(t *testing.T) {
	t0 := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	records := []evidence.Record{
		rec("cfr-part-11-10a-system-validation", oscal.StatusSatisfied, t0),
	}
	cw := Crosswalk{Mappings: []Mapping{{
		Control:     "dora-9-2-ict-supply-chain",
		SatisfiedBy: []string{"cfr-part-11-10a-system-validation"},
	}}}

	derived := Apply(records, cw)

	if len(derived) != 1 {
		t.Fatalf("want 1 derived record, got %d", len(derived))
	}
	d := derived[0]
	if d.ControlID != "dora-9-2-ict-supply-chain" {
		t.Errorf("control id = %q, want dora-9-2-ict-supply-chain", d.ControlID)
	}
	if d.Result != oscal.StatusSatisfied {
		t.Errorf("result = %q, want satisfied", d.Result)
	}
	if !d.ObservedAt.Equal(t0) {
		t.Errorf("observed-at = %v, want %v", d.ObservedAt, t0)
	}
	// The derived record must trace back to the anchor that answers it, so a
	// reviewer can see the one control answering both frameworks.
	if d.Source == "" {
		t.Error("derived record has no source pointing at its anchor controls")
	}
}

func TestApplyTargetNotSatisfiedWhenAnchorNotSatisfied(t *testing.T) {
	t0 := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	records := []evidence.Record{
		rec("cfr-part-11-10a-system-validation", oscal.StatusNotSatisfied, t0),
	}
	cw := Crosswalk{Mappings: []Mapping{{
		Control:     "dora-9-2-ict-supply-chain",
		SatisfiedBy: []string{"cfr-part-11-10a-system-validation"},
	}}}

	derived := Apply(records, cw)

	if len(derived) != 1 || derived[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("want one not-satisfied derived record, got %+v", derived)
	}
}

func TestApplyTargetNotSatisfiedWhenAnchorMissing(t *testing.T) {
	cw := Crosswalk{Mappings: []Mapping{{
		Control:     "dora-9-2-ict-supply-chain",
		SatisfiedBy: []string{"cfr-part-11-10a-system-validation"},
	}}}

	derived := Apply(nil, cw)

	if len(derived) != 1 || derived[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("want one not-satisfied derived record for missing anchor, got %+v", derived)
	}
}

func TestApplyTargetNeedsAllAnchorsSatisfied(t *testing.T) {
	t0 := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	records := []evidence.Record{
		rec("cfr-part-11-10a-system-validation", oscal.StatusSatisfied, t0),
		rec("eu-ai-act-12-record-keeping", oscal.StatusNotSatisfied, t1),
	}
	cw := Crosswalk{Mappings: []Mapping{{
		Control:     "nis2-21-2-d-supply-chain",
		SatisfiedBy: []string{"cfr-part-11-10a-system-validation", "eu-ai-act-12-record-keeping"},
	}}}

	derived := Apply(records, cw)

	if len(derived) != 1 || derived[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("want not-satisfied when one of several anchors fails, got %+v", derived)
	}
}

func TestApplyUsesLatestStatusPerAnchor(t *testing.T) {
	t0 := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	// A lapse followed by a recovery: the current status is satisfied, matching
	// posture's latest-observation rule.
	records := []evidence.Record{
		rec("anchor", oscal.StatusNotSatisfied, t0),
		rec("anchor", oscal.StatusSatisfied, t1),
	}
	cw := Crosswalk{Mappings: []Mapping{{Control: "target", SatisfiedBy: []string{"anchor"}}}}

	derived := Apply(records, cw)

	if len(derived) != 1 || derived[0].Result != oscal.StatusSatisfied {
		t.Fatalf("want satisfied from latest anchor observation, got %+v", derived)
	}
}

func TestApplyDerivedObservedAtIsLatestAnchor(t *testing.T) {
	t0 := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(48 * time.Hour)
	records := []evidence.Record{
		rec("a", oscal.StatusSatisfied, t0),
		rec("b", oscal.StatusSatisfied, t1),
	}
	cw := Crosswalk{Mappings: []Mapping{{Control: "target", SatisfiedBy: []string{"a", "b"}}}}

	derived := Apply(records, cw)

	if !derived[0].ObservedAt.Equal(t1) {
		t.Errorf("observed-at = %v, want latest anchor time %v", derived[0].ObservedAt, t1)
	}
}

func TestApplyPreservesMappingOrder(t *testing.T) {
	cw := Crosswalk{Mappings: []Mapping{
		{Control: "first", SatisfiedBy: []string{"x"}},
		{Control: "second", SatisfiedBy: []string{"y"}},
	}}

	derived := Apply(nil, cw)

	if len(derived) != 2 || derived[0].ControlID != "first" || derived[1].ControlID != "second" {
		t.Fatalf("derived records out of mapping order: %+v", derived)
	}
}
