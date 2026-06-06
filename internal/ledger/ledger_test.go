package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
)

func record(control, subject string) evidence.Record {
	return evidence.Record{
		ControlID: control,
		Subject:   subject,
		Result:    "satisfied",
		Source:    "github/pull-request#1",
	}
}

func TestAppendThenEntriesRoundTrips(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "ledger.jsonl"))

	if _, err := l.Append(record("annex11-10-change-control", "commit/a")); err != nil {
		t.Fatalf("Append a: %v", err)
	}
	if _, err := l.Append(record("annex11-9-audit-trail", "commit/b")); err != nil {
		t.Fatalf("Append b: %v", err)
	}

	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if entries[0].Record.Subject != "commit/a" || entries[1].Record.Subject != "commit/b" {
		t.Errorf("entries out of order: %q, %q", entries[0].Record.Subject, entries[1].Record.Subject)
	}
	if entries[0].Record.ControlID != "annex11-10-change-control" {
		t.Errorf("record not preserved: %+v", entries[0].Record)
	}
}

func TestVerifyPassesForIntactLedger(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "ledger.jsonl"))
	for _, s := range []string{"commit/a", "commit/b", "commit/c"} {
		if _, err := l.Append(record("annex11-10-change-control", s)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Verify(); err != nil {
		t.Errorf("Verify on an intact ledger: %v", err)
	}
}

func TestVerifyDetectsMutatedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l := Open(path)
	for _, s := range []string{"commit/a", "commit/b"} {
		if _, err := l.Append(record("annex11-10-change-control", s)); err != nil {
			t.Fatal(err)
		}
	}
	// Mutate a stored record's payload without recomputing its hash.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), "satisfied", "not-satisfied", 1)
	if tampered == string(data) {
		t.Fatal("test setup: nothing was mutated")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := l.Verify(); err == nil {
		t.Error("expected Verify to detect a mutated record")
	}
}

func TestVerifyDetectsDeletedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l := Open(path)
	for _, s := range []string{"commit/a", "commit/b", "commit/c"} {
		if _, err := l.Append(record("annex11-10-change-control", s)); err != nil {
			t.Fatal(err)
		}
	}
	// Remove the middle entry, breaking the chain linkage.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	kept := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(kept), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := l.Verify(); err == nil {
		t.Error("expected Verify to detect a deleted entry")
	}
}

func TestEntriesEmptyForNewLedger(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "ledger.jsonl"))
	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries on empty ledger: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("want no entries for a fresh ledger, got %d", len(entries))
	}
}
