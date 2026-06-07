package posture

import (
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
)

func TestTrendEmptyForNoRecords(t *testing.T) {
	if pts := TrendOf(nil).Points; len(pts) != 0 {
		t.Fatalf("want no trend points for no records, got %d", len(pts))
	}
}

// The trend is the coverage timeline: after each observation, how many controls
// are known and how many of them are currently satisfied (latest wins).
func TestTrendTracksCoverageOverTime(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)
	records := []evidence.Record{
		rec("c1", "satisfied", t0),     // 1 known, 1 satisfied
		rec("c2", "not-satisfied", t1), // 2 known, 1 satisfied
		rec("c2", "satisfied", t2),     // 2 known, 2 satisfied (c2 recovers)
	}

	tr := TrendOf(records)
	if len(tr.Points) != 3 {
		t.Fatalf("want 3 trend points, got %d: %+v", len(tr.Points), tr.Points)
	}
	want := []TrendPoint{
		{At: t0, Total: 1, Satisfied: 1},
		{At: t1, Total: 2, Satisfied: 1},
		{At: t2, Total: 2, Satisfied: 2},
	}
	for i, w := range want {
		got := tr.Points[i]
		if !got.At.Equal(w.At) || got.Total != w.Total || got.Satisfied != w.Satisfied {
			t.Errorf("point %d = %+v, want %+v", i, got, w)
		}
	}
}

// Records observed at the same instant collapse into a single point reflecting
// the state after all of them, so the timeline has one entry per moment.
func TestTrendCollapsesSameTimestamp(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	records := []evidence.Record{
		rec("c1", "satisfied", t0),
		rec("c2", "not-satisfied", t0),
	}
	tr := TrendOf(records)
	if len(tr.Points) != 1 {
		t.Fatalf("want a single collapsed point, got %d: %+v", len(tr.Points), tr.Points)
	}
	if tr.Points[0].Total != 2 || tr.Points[0].Satisfied != 1 {
		t.Errorf("collapsed point = %+v, want total 2 / satisfied 1", tr.Points[0])
	}
}

// Out-of-order input is sorted into a chronological timeline.
func TestTrendIsChronological(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	records := []evidence.Record{
		rec("c1", "satisfied", t1),
		rec("c1", "not-satisfied", t0),
	}
	tr := TrendOf(records)
	if len(tr.Points) != 2 {
		t.Fatalf("want 2 points, got %d", len(tr.Points))
	}
	if tr.Points[0].At.After(tr.Points[1].At) {
		t.Errorf("points not chronological: %v then %v", tr.Points[0].At, tr.Points[1].At)
	}
	// The earlier observation (not-satisfied) must be reflected first, then the
	// later recovery.
	if tr.Points[0].Satisfied != 0 || tr.Points[1].Satisfied != 1 {
		t.Errorf("coverage did not follow chronological order: %+v", tr.Points)
	}
}
