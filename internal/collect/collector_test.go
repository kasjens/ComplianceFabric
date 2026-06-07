package collect

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/ledger"
)

func syncedApps(status string) []byte {
	return []byte(`{"items":[{"metadata":{"name":"web"},"status":{"sync":{"status":"` + status + `"},"reconciledAt":"2026-01-01T00:00:00Z"}}]}`)
}

// A tick fetches each source, produces records, and appends only the changes to
// the ledger; an identical second tick appends nothing (event-log semantics end
// to end through the collector and its ledger).
func TestCollectorTickAppendsOnlyChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	led := ledger.Open(path)

	payload := syncedApps("Synced")
	c := &Collector{
		Ledger: led,
		Fetch:  func(_ []string) ([]byte, error) { return payload, nil },
		Sources: []Source{{
			Type:    "drift",
			Command: []string{"kubectl", "get", "applications"},
			Params:  Params{ControlID: "annex11-11-periodic-evaluation"},
		}},
	}

	changed, err := c.Tick()
	if err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if len(changed) != 1 {
		t.Fatalf("first tick should record the baseline, appended %d", len(changed))
	}

	changed, err = c.Tick()
	if err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if len(changed) != 0 {
		t.Fatalf("an unchanged second tick should append nothing, appended %d", len(changed))
	}

	// The ledger holds exactly the one baseline entry and still verifies.
	entries, err := led.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ledger should hold 1 entry after two unchanged ticks, has %d", len(entries))
	}
	if err := led.Verify(); err != nil {
		t.Fatalf("ledger should verify: %v", err)
	}
}

// When the observed state transitions, the next tick records the event.
func TestCollectorTickRecordsTransition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	led := ledger.Open(path)

	payload := syncedApps("Synced")
	c := &Collector{
		Ledger:  led,
		Fetch:   func(_ []string) ([]byte, error) { return payload, nil },
		Sources: []Source{{Type: "drift", Command: []string{"x"}, Params: Params{ControlID: "c1"}}},
	}
	if _, err := c.Tick(); err != nil {
		t.Fatalf("baseline tick: %v", err)
	}

	payload = syncedApps("OutOfSync") // the app drifts
	changed, err := c.Tick()
	if err != nil {
		t.Fatalf("transition tick: %v", err)
	}
	if len(changed) != 1 {
		t.Fatalf("the drift transition should be recorded once, appended %d", len(changed))
	}
}

// A failing source must not abort the others: the healthy source's evidence is
// still collected, and the tick reports the failure.
func TestCollectorTickIsResilientToSourceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	led := ledger.Open(path)

	c := &Collector{
		Ledger: led,
		Fetch: func(cmd []string) ([]byte, error) {
			if cmd[0] == "broken" {
				return nil, errors.New("command not found")
			}
			return syncedApps("Synced"), nil
		},
		Sources: []Source{
			{Type: "drift", Command: []string{"broken"}, Params: Params{ControlID: "c1"}},
			{Type: "drift", Command: []string{"ok"}, Params: Params{ControlID: "c2"}},
		},
	}

	changed, err := c.Tick()
	if err == nil {
		t.Fatal("expected the failing source to be reported as an error")
	}
	if len(changed) != 1 {
		t.Fatalf("the healthy source should still be collected, appended %d", len(changed))
	}
}
