package ledger

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

func rec(subject string) evidence.Record {
	return evidence.Record{
		ControlID:  "cfr-part-11-10a-system-validation",
		Subject:    subject,
		Result:     oscal.StatusSatisfied,
		ObservedAt: time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC),
		Source:     "repro",
	}
}

// Entries() uses a default bufio.Scanner, whose line cap is 64 KB. A single
// oversized record — an SBOM inventory is routinely larger — makes Entries()
// return an error, which renders the ENTIRE ledger unreadable, including every
// prior valid entry. Verify() and any further Append() fail with it, so the
// evidence store becomes permanently inaccessible rather than degrading.
func TestOversizedRecordMustNotBreakLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	l := Open(path)

	if _, err := l.Append(rec("small-before")); err != nil {
		t.Fatalf("append small: %v", err)
	}

	// ~128 KB of payload, comfortably past the 64 KB scanner cap and well within
	// what a real SBOM or policy-report record reaches.
	big := rec(strings.Repeat("A", 128*1024))
	if _, err := l.Append(big); err != nil {
		t.Fatalf("append oversized record: %v", err)
	}

	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries() after one oversized record: %v\n"+
			"a single >64KB record made the whole ledger unreadable, "+
			"including the valid entry written before it", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if got := entries[1].Record.Subject; len(got) != 128*1024 {
		t.Errorf("oversized record round-tripped at %d bytes, want %d", len(got), 128*1024)
	}

	if err := l.Verify(); err != nil {
		t.Errorf("Verify() after oversized record: %v", err)
	}

	// The ledger must still be appendable afterwards.
	if _, err := l.Append(rec("small-after")); err != nil {
		t.Errorf("append after oversized record: %v", err)
	}
}
