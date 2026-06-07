package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

// Limits is one agent's per-window budget. MaxRequests caps how many
// interactions the agent may run in a Window; MaxCost caps the cost it may
// accumulate in the same Window. A zero on either axis means unlimited on that
// axis, and a zero Window means the budget is for the limiter's lifetime (it
// never resets). Costs are caller-asserted, the same way the model allow-list
// screens the model a request declares: the gateway bounds what the caller says
// each interaction will cost.
type Limits struct {
	MaxRequests int           `json:"max-requests"`
	MaxCost     float64       `json:"max-cost"`
	Window      time.Duration `json:"window"`
}

// UnmarshalJSON decodes a Limits from a config object whose window is a
// human-readable duration string ("1h", "30m") rather than a raw nanosecond
// count, so an operator authoring a limits file never writes nanoseconds. An
// omitted or empty window is a lifetime budget (zero Window).
func (l *Limits) UnmarshalJSON(data []byte) error {
	var raw struct {
		MaxRequests int     `json:"max-requests"`
		MaxCost     float64 `json:"max-cost"`
		Window      string  `json:"window"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	l.MaxRequests = raw.MaxRequests
	l.MaxCost = raw.MaxCost
	if raw.Window != "" {
		d, err := time.ParseDuration(raw.Window)
		if err != nil {
			return fmt.Errorf("invalid window %q: %w", raw.Window, err)
		}
		l.Window = d
	}
	return nil
}

// LoadLimits reads a JSON file mapping each agent id to its budget and returns
// the map NewLimiter consumes. The file's window fields are human-readable
// durations (see Limits.UnmarshalJSON). A missing file or any malformed entry is
// an error, so the gateway never starts serving with a limits file it could not
// fully apply.
func LoadLimits(path string) (map[string]Limits, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var limits map[string]Limits
	if err := json.Unmarshal(data, &limits); err != nil {
		return nil, err
	}
	return limits, nil
}

// Limiter enforces per-agent rate and cost budgets across interactions. It is the
// third gate after registration and content screening: even a registered agent
// running a declared prompt with clean input is blocked once it exhausts its
// budget in the current window, which bounds runaway request volume and cost from
// a non-deterministic agent. It is safe for concurrent use.
type Limiter struct {
	limits map[string]Limits
	mu     sync.Mutex
	state  map[string]*window
}

// window is one agent's current fixed-window tally: when the window started and
// how many requests and how much cost have been charged in it.
type window struct {
	start    time.Time
	requests int
	cost     float64
}

// NewLimiter builds a limiter from per-agent limits. An agent absent from the map
// is unlimited.
func NewLimiter(limits map[string]Limits) *Limiter {
	return &Limiter{limits: limits, state: map[string]*window{}}
}

// Charge attempts to record one interaction of the given cost for the agent at
// time now, returning an allow Decision when it fits the agent's budget and a deny
// Decision naming the breached axis (rate or cost) when it does not. A denied
// charge consumes no budget, so a blocked request does not count against a later
// one. A nil limiter, an unconfigured agent, or a zero limit on an axis all allow.
func (l *Limiter) Charge(agent string, cost float64, now time.Time) Decision {
	if l == nil {
		return Decision{Allowed: true}
	}
	lim, ok := l.limits[agent]
	if !ok {
		return Decision{Allowed: true}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	w := l.state[agent]
	if w == nil || (lim.Window > 0 && now.Sub(w.start) >= lim.Window) {
		w = &window{start: now}
		l.state[agent] = w
	}

	if lim.MaxRequests > 0 && w.requests+1 > lim.MaxRequests {
		return Decision{Allowed: false, Reason: "agent " + agent +
			" exceeded its request rate limit (" + strconv.Itoa(lim.MaxRequests) + " per window)"}
	}
	if lim.MaxCost > 0 && w.cost+cost > lim.MaxCost {
		return Decision{Allowed: false, Reason: "agent " + agent +
			" exceeded its cost budget (max " + strconv.FormatFloat(lim.MaxCost, 'g', -1, 64) + " per window)"}
	}

	w.requests++
	w.cost += cost
	return Decision{Allowed: true}
}
