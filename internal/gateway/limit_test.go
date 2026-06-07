package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(min int) time.Time {
	return time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
}

func TestLimiterAllowsWithinRequestBudgetThenBlocks(t *testing.T) {
	l := NewLimiter(map[string]Limits{
		"release-reviewer": {MaxRequests: 3, Window: time.Minute},
	})
	for i := 0; i < 3; i++ {
		if d := l.Charge("release-reviewer", 0, at(0)); !d.Allowed {
			t.Fatalf("request %d within budget should be allowed, got %q", i+1, d.Reason)
		}
	}
	d := l.Charge("release-reviewer", 0, at(0))
	if d.Allowed {
		t.Fatal("the 4th request in the window should be blocked")
	}
	if !strings.Contains(d.Reason, "rate") {
		t.Errorf("expected a rate-limit reason, got %q", d.Reason)
	}
}

func TestLimiterResetsRequestCountAfterWindow(t *testing.T) {
	l := NewLimiter(map[string]Limits{
		"a": {MaxRequests: 1, Window: time.Minute},
	})
	if d := l.Charge("a", 0, at(0)); !d.Allowed {
		t.Fatalf("first request should be allowed, got %q", d.Reason)
	}
	if d := l.Charge("a", 0, at(0)); d.Allowed {
		t.Fatal("second request in the same window should be blocked")
	}
	// A request in the next window starts a fresh count.
	if d := l.Charge("a", 0, at(2)); !d.Allowed {
		t.Fatalf("request in the next window should be allowed, got %q", d.Reason)
	}
}

func TestLimiterEnforcesCostBudget(t *testing.T) {
	l := NewLimiter(map[string]Limits{
		"a": {MaxCost: 1.0, Window: time.Minute},
	})
	if d := l.Charge("a", 0.6, at(0)); !d.Allowed {
		t.Fatalf("0.6 within a 1.0 budget should be allowed, got %q", d.Reason)
	}
	// 0.6 + 0.6 = 1.2 exceeds the budget; this is blocked and must not consume.
	if d := l.Charge("a", 0.6, at(0)); d.Allowed {
		t.Fatal("a charge that would exceed the cost budget should be blocked")
	} else if !strings.Contains(d.Reason, "cost") {
		t.Errorf("expected a cost-budget reason, got %q", d.Reason)
	}
	// The blocked 0.6 did not consume budget, so 0.4 (total 1.0) still fits.
	if d := l.Charge("a", 0.4, at(0)); !d.Allowed {
		t.Fatalf("0.4 bringing the total to exactly 1.0 should be allowed, got %q", d.Reason)
	}
}

func TestLimiterUnconfiguredAgentIsUnlimited(t *testing.T) {
	l := NewLimiter(map[string]Limits{
		"a": {MaxRequests: 1, Window: time.Minute},
	})
	for i := 0; i < 100; i++ {
		if d := l.Charge("other-agent", 99, at(0)); !d.Allowed {
			t.Fatalf("an agent with no configured limits should be unlimited, got %q", d.Reason)
		}
	}
}

func TestLimiterZeroLimitsMeanUnlimited(t *testing.T) {
	l := NewLimiter(map[string]Limits{
		"a": {MaxRequests: 0, MaxCost: 0, Window: time.Minute},
	})
	for i := 0; i < 100; i++ {
		if d := l.Charge("a", 99, at(0)); !d.Allowed {
			t.Fatalf("zero limits should mean unlimited on that axis, got %q", d.Reason)
		}
	}
}

func TestLimiterIsPerAgent(t *testing.T) {
	l := NewLimiter(map[string]Limits{
		"a": {MaxRequests: 1, Window: time.Minute},
		"b": {MaxRequests: 1, Window: time.Minute},
	})
	if d := l.Charge("a", 0, at(0)); !d.Allowed {
		t.Fatalf("agent a first request should be allowed, got %q", d.Reason)
	}
	// b has its own budget, untouched by a.
	if d := l.Charge("b", 0, at(0)); !d.Allowed {
		t.Fatalf("agent b should have its own budget, got %q", d.Reason)
	}
}

// A nil limiter enforces nothing, so a server with no limits configured admits
// everything on the budget axis.
func TestNilLimiterAllows(t *testing.T) {
	var l *Limiter
	if d := l.Charge("a", 1000, at(0)); !d.Allowed {
		t.Fatalf("a nil limiter should allow, got %q", d.Reason)
	}
}

// LoadLimits reads a JSON map of agent to budget, parsing the window as a
// human-readable duration ("1h", "30m") so an operator never has to write
// nanoseconds.
func TestLoadLimitsParsesHumanDurations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "limits.json")
	body := `{
		"release-reviewer": {"max-requests": 100, "max-cost": 5.0, "window": "1h"},
		"triager": {"max-requests": 10, "window": "30m"}
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	limits, err := LoadLimits(path)
	if err != nil {
		t.Fatalf("LoadLimits: %v", err)
	}
	rr, ok := limits["release-reviewer"]
	if !ok {
		t.Fatal("expected release-reviewer in limits")
	}
	if rr.MaxRequests != 100 || rr.MaxCost != 5.0 || rr.Window != time.Hour {
		t.Errorf("release-reviewer = %+v, want {100 5 1h}", rr)
	}
	if tr := limits["triager"]; tr.MaxRequests != 10 || tr.Window != 30*time.Minute {
		t.Errorf("triager = %+v, want {10 0 30m}", tr)
	}

	// The loaded budget enforces as configured: the 11th triager request is blocked.
	l := NewLimiter(limits)
	for i := 0; i < 10; i++ {
		if d := l.Charge("triager", 0, at(0)); !d.Allowed {
			t.Fatalf("triager request %d should fit, got %q", i+1, d.Reason)
		}
	}
	if d := l.Charge("triager", 0, at(0)); d.Allowed {
		t.Error("the 11th triager request should be blocked")
	}
}

func TestLoadLimitsRejectsBadDuration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(path, []byte(`{"a": {"window": "1 fortnight"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLimits(path); err == nil {
		t.Fatal("expected an error for an unparseable window duration")
	}
}

func TestLoadLimitsMissingFile(t *testing.T) {
	if _, err := LoadLimits(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected an error for a missing limits file")
	}
}

// A window may be omitted to mean a lifetime budget (the limiter never resets).
func TestLoadLimitsAllowsOmittedWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(path, []byte(`{"a": {"max-requests": 2}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	limits, err := LoadLimits(path)
	if err != nil {
		t.Fatalf("LoadLimits: %v", err)
	}
	if a := limits["a"]; a.MaxRequests != 2 || a.Window != 0 {
		t.Errorf("a = %+v, want {2 0 0}", a)
	}
}
