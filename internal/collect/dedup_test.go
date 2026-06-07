package collect

import (
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

func rec(control, subject, result string) evidence.Record {
	return evidence.Record{
		ControlID:  control,
		Subject:    subject,
		Result:     result,
		ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Source:     "test",
	}
}

// The first time a (control, subject) is observed there is no prior state, so the
// observation is a change and must be kept — it establishes the baseline.
func TestDedupKeepsFirstObservation(t *testing.T) {
	got := Dedup(nil, []evidence.Record{rec("c1", "app/web", oscal.StatusSatisfied)})
	if len(got) != 1 {
		t.Fatalf("expected the first observation to be kept, got %d records", len(got))
	}
}

// An observation identical to the latest reflected state is not a change, so the
// event-log ledger must not record it again. This is what keeps continuous
// collection from appending the same "still satisfied" row every interval.
func TestDedupDropsUnchangedObservation(t *testing.T) {
	prior := []evidence.Record{rec("c1", "app/web", oscal.StatusSatisfied)}
	got := Dedup(prior, []evidence.Record{rec("c1", "app/web", oscal.StatusSatisfied)})
	if len(got) != 0 {
		t.Fatalf("expected an unchanged observation to be dropped, got %d records", len(got))
	}
}

// A result that differs from the latest reflected state is a transition, the
// event worth recording.
func TestDedupKeepsTransition(t *testing.T) {
	prior := []evidence.Record{rec("c1", "app/web", oscal.StatusSatisfied)}
	got := Dedup(prior, []evidence.Record{rec("c1", "app/web", oscal.StatusNotSatisfied)})
	if len(got) != 1 || got[0].Result != oscal.StatusNotSatisfied {
		t.Fatalf("expected the transition to be kept, got %v", got)
	}
}

// The latest record per key (not the first) defines the reflected state, so a key
// that flapped and settled is compared against where it settled.
func TestDedupComparesAgainstLatestPriorPerKey(t *testing.T) {
	prior := []evidence.Record{
		rec("c1", "app/web", oscal.StatusSatisfied),
		rec("c1", "app/web", oscal.StatusNotSatisfied), // latest reflected state
	}
	// Observing not-satisfied again is no change versus the latest.
	got := Dedup(prior, []evidence.Record{rec("c1", "app/web", oscal.StatusNotSatisfied)})
	if len(got) != 0 {
		t.Fatalf("expected no change versus the latest prior state, got %v", got)
	}
}

// A key is identified by control and subject together, so the same subject under a
// different control is a distinct key.
func TestDedupDistinguishesKeysByControlAndSubject(t *testing.T) {
	prior := []evidence.Record{rec("c1", "app/web", oscal.StatusSatisfied)}
	got := Dedup(prior, []evidence.Record{
		rec("c2", "app/web", oscal.StatusSatisfied), // different control -> new key
		rec("c1", "app/api", oscal.StatusSatisfied), // different subject -> new key
	})
	if len(got) != 2 {
		t.Fatalf("expected both distinct keys to be kept, got %d", len(got))
	}
}

// Within a single tick the same key observed twice with the same result is one
// event: the second identical observation is dropped against the first.
func TestDedupCollapsesIdenticalWithinTick(t *testing.T) {
	got := Dedup(nil, []evidence.Record{
		rec("c1", "app/web", oscal.StatusSatisfied),
		rec("c1", "app/web", oscal.StatusSatisfied),
	})
	if len(got) != 1 {
		t.Fatalf("expected identical within-tick observations to collapse to one, got %d", len(got))
	}
}
