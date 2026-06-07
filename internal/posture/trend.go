package posture

import (
	"sort"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// TrendPoint is the control coverage as of one observed moment: how many controls
// have been seen by then (Total) and how many of those are currently satisfied
// (Satisfied, latest-result-wins per control).
type TrendPoint struct {
	At        time.Time
	Total     int
	Satisfied int
}

// Trend is the coverage-over-time series the posture dashboard plots: where the
// per-control rollup answers "where do we stand now", the trend answers "how did
// we get here". Because the ledger is an append-only event log of state changes,
// the trend is a faithful history rather than a sampled approximation.
type Trend struct {
	Points []TrendPoint
}

// TrendOf builds the coverage timeline from a set of evidence records. It replays
// the records in chronological order (ties broken by append order, so the ledger's
// causal sequence is preserved), tracking the latest result per control, and emits
// one point per distinct moment giving the satisfied/total coverage as of then.
func TrendOf(records []evidence.Record) Trend {
	ordered := make([]evidence.Record, len(records))
	copy(ordered, records)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].ObservedAt.Before(ordered[j].ObservedAt)
	})

	latest := map[string]string{}
	var points []TrendPoint
	for _, r := range ordered {
		latest[r.ControlID] = r.Result

		satisfied := 0
		for _, result := range latest {
			if result == oscal.StatusSatisfied {
				satisfied++
			}
		}
		point := TrendPoint{At: r.ObservedAt, Total: len(latest), Satisfied: satisfied}

		// Records observed at the same instant collapse into one point reflecting
		// the state after all of them.
		if n := len(points); n > 0 && points[n-1].At.Equal(r.ObservedAt) {
			points[n-1] = point
			continue
		}
		points = append(points, point)
	}
	return Trend{Points: points}
}
