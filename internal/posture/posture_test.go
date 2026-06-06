package posture

import (
	"strings"
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
)

func rec(control, result string, observedAt time.Time) evidence.Record {
	return evidence.Record{
		ControlID:  control,
		Result:     result,
		ObservedAt: observedAt,
		Source:     "github/pull-request#1",
	}
}

func TestSummarizeUsesLatestRecordPerControl(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	// Out of chronological order on purpose: the latest observation wins.
	records := []evidence.Record{
		rec("annex11-10-change-control", "satisfied", t1),
		rec("annex11-10-change-control", "not-satisfied", t0),
	}

	p := Summarize(records)
	if len(p.Controls) != 1 {
		t.Fatalf("want one control, got %d", len(p.Controls))
	}
	c := p.Controls[0]
	if c.Status != "satisfied" {
		t.Errorf("current status = %q, want satisfied (the latest record)", c.Status)
	}
	if c.Records != 2 {
		t.Errorf("record count = %d, want 2", c.Records)
	}
	if c.Lapses != 1 {
		t.Errorf("lapses = %d, want 1 not-satisfied observation in history", c.Lapses)
	}
	if !c.LastObserved.Equal(t1) {
		t.Errorf("last observed = %v, want %v", c.LastObserved, t1)
	}
}

func TestSummarizeSortsControlsByID(t *testing.T) {
	now := time.Now()
	records := []evidence.Record{
		rec("cfr-part-11-10a", "satisfied", now),
		rec("annex11-10-change-control", "satisfied", now),
	}
	p := Summarize(records)
	if len(p.Controls) != 2 {
		t.Fatalf("want two controls, got %d", len(p.Controls))
	}
	if p.Controls[0].ControlID != "annex11-10-change-control" {
		t.Errorf("controls not sorted by id: %q first", p.Controls[0].ControlID)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	p := Summarize(nil)
	if len(p.Controls) != 0 {
		t.Errorf("want no controls for no records, got %d", len(p.Controls))
	}
}

func TestNotSatisfiedReturnsCurrentGaps(t *testing.T) {
	now := time.Now()
	records := []evidence.Record{
		rec("control-ok", "satisfied", now),
		rec("control-gap", "not-satisfied", now),
	}
	gaps := Summarize(records).NotSatisfied()
	if len(gaps) != 1 {
		t.Fatalf("want one current gap, got %d", len(gaps))
	}
	if gaps[0].ControlID != "control-gap" {
		t.Errorf("gap control = %q, want control-gap", gaps[0].ControlID)
	}
}

func TestRenderShowsControlsAndSummary(t *testing.T) {
	now := time.Now()
	out := Summarize([]evidence.Record{
		rec("annex11-10-change-control", "satisfied", now),
		rec("control-gap", "not-satisfied", now),
	}).Render()

	if !strings.Contains(out, "annex11-10-change-control") {
		t.Errorf("render missing a control id:\n%s", out)
	}
	if !strings.Contains(out, "not-satisfied") {
		t.Errorf("render missing a status:\n%s", out)
	}
	if !strings.Contains(out, "2 controls") {
		t.Errorf("render missing a summary count:\n%s", out)
	}
}
