package posture

import (
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// REPRODUCTION — Workstream R.2, plan items 3.3 and 3.4. Expected to FAIL
// against cac9f78.

func at(h, m int) time.Time { return time.Date(2026, 7, 1, h, m, 0, 0, time.UTC) }

// 3.3 — Summarize keys byControl on ControlID ALONE and discards Subject. Every
// producer emits distinct subjects (Argo apps, gateway interactions, SBOM
// components), so two subjects under one control collapse into a single row and
// the LATEST record wins outright. A failing subject is therefore masked by any
// passing subject observed after it: the control reads green, and NotSatisfied()
// — the list a reviewer acts on — omits it entirely.
func TestRepro33FailingSubjectMustNotBeMaskedByAnother(t *testing.T) {
	records := []evidence.Record{
		{ControlID: "CM-2", Subject: "argo/payments", Result: oscal.StatusNotSatisfied, ObservedAt: at(10, 0)},
		{ControlID: "CM-2", Subject: "argo/billing", Result: oscal.StatusSatisfied, ObservedAt: at(10, 5)},
	}

	p := Summarize(records)

	var cm2 ControlPosture
	for _, c := range p.Controls {
		if c.ControlID == "CM-2" {
			cm2 = c
		}
	}

	if cm2.Status == oscal.StatusSatisfied {
		t.Errorf("CM-2 reports %q even though subject argo/payments is not-satisfied; "+
			"a passing subject observed 5 minutes later masked a real drift", cm2.Status)
	}
	if len(p.NotSatisfied()) == 0 {
		t.Error("NotSatisfied() is empty, so the failing subject is invisible to the " +
			"reviewer, the dashboard and /posture.json")
	}

	// The lapse COUNT does still increment — the plan's revision-3 correction.
	// Recorded here so a fix does not regress it.
	if cm2.Lapses != 1 {
		t.Errorf("expected the masked record to still count as a lapse, got %d", cm2.Lapses)
	}
}

// 3.4 — an absent optional timestamp becomes time.Unix(0,0) = 1970, which is NOT
// IsZero(), so the escape hatch in Summarize never fires. A newer FAILING
// observation carrying a missing timestamp sorts to 1970, loses the
// latest-wins comparison, and the stale green is preserved.
func TestRepro34EpochTimestampMustNotFreezeStaleGreen(t *testing.T) {
	records := []evidence.Record{
		{ControlID: "PART11-3", Subject: "ns/prod/Pod/api", Result: oscal.StatusSatisfied, ObservedAt: at(9, 0)},
		// Appended later, but its timestamp was missing and became epoch.
		{ControlID: "PART11-3", Subject: "ns/prod/Pod/api", Result: oscal.StatusNotSatisfied, ObservedAt: time.Unix(0, 0).UTC()},
	}

	p := Summarize(records)
	if p.Controls[0].Status == oscal.StatusSatisfied {
		t.Errorf("PART11-3 still reports %q after a failing observation was appended; "+
			"the failure carried a 1970 timestamp and lost the latest-wins comparison",
			p.Controls[0].Status)
	}
}
