package ledger

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

// 4.1 — Append re-reads the whole file to find the head, computes the chain hash,
// then opens the file O_APPEND and writes. There is no file lock and no in-process
// mutex, so two concurrent appends read the SAME head and both write an entry
// carrying the same PrevHash. Verify() then fails forever, and the failure is
// INDISTINGUISHABLE FROM TAMPERING — which is the one thing an evidence ledger
// must never be ambiguous about. There is no repair path.
func TestConcurrentAppendsMustNotCorruptChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	l := Open(path)

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := l.Append(rec("subject-" + strconv.Itoa(i))); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Append failed: %v", err)
	}

	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries() after concurrent appends: %v", err)
	}
	if len(entries) != n {
		t.Errorf("got %d entries, want %d — an append was lost", len(entries), n)
	}
	if err := l.Verify(); err != nil {
		t.Errorf("Verify() after %d concurrent appends: %v\n"+
			"the chain is broken by concurrency alone, which is indistinguishable "+
			"from tampering and has no repair path", n, err)
	}
}

// 4.4(a) — the package doc claims "any later mutation or deletion of a stored
// entry breaks the chain and is detectable by Verify". That is FALSE for deletion
// at the tail: dropping the last line leaves a shorter but perfectly self-
// consistent chain, and Verify returns nil. `head -n -1 ledger.jsonl` silently
// destroys evidence.
func TestTailTruncationMustBeDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	l := Open(path)

	for i := 0; i < 3; i++ {
		if _, err := l.Append(rec("subject-" + strconv.Itoa(i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("baseline Verify: %v", err)
	}

	// Drop the final entry, the way `head -n -1` would.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 stored lines, got %d", len(lines))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := l.Verify(); err == nil {
		t.Error("Verify() accepted a ledger whose last entry was deleted; " +
			"the package doc's tamper-evidence claim does not hold for tail truncation")
	}
}
