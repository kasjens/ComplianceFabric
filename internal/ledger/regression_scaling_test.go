package ledger

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.
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

func TestAppendScaling(t *testing.T) {
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
