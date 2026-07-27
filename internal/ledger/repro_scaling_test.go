package ledger

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// REPRODUCTION — Workstream R.2, plan item 4.2.
//
// Append calls Entries(), which re-reads and re-parses the ENTIRE file, before
// every single write. Building a ledger of n records is therefore O(n^2), and
// collector.Tick appends in a loop. This is a performance characteristic rather
// than a correctness bug, so it is measured rather than asserted on a fixed
// threshold: doubling the record count should roughly double the work (linear),
// but quadratic growth quadruples it.
func appendN(t *testing.T, n int) time.Duration {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	l := Open(path)

	start := time.Now()
	for i := 0; i < n; i++ {
		if _, err := l.Append(rec("subject-" + strconv.Itoa(i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return time.Since(start)
}

func TestRepro42AppendScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling measurement")
	}

	const base = 500
	d1 := appendN(t, base)
	d2 := appendN(t, base*2)

	ratio := float64(d2) / float64(d1)
	t.Logf("append %d records: %v", base, d1)
	t.Logf("append %d records: %v", base*2, d2)
	t.Logf("doubling ratio: %.2fx (linear ~2x, quadratic ~4x)", ratio)

	// Deliberately generous: only flag clearly super-linear growth, so this does
	// not become a flaky test on a loaded machine.
	if ratio > 3.0 {
		t.Errorf("doubling the record count multiplied the work by %.2fx, which is "+
			"super-linear: Append re-reads the whole ledger before every write, so "+
			"building an n-record ledger is O(n^2)", ratio)
	}
}
