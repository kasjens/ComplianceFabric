package gateway

import (
	"math"
	"testing"
	"time"
)

// REPRODUCTION — Workstream R.2, plan item 1.6. Expected to FAIL against cac9f78.

// The cost is taken from a client-supplied X-Fabric-Cost header and passed to
// Charge unvalidated. strconv.ParseFloat accepts "NaN", "Inf" and negatives.
//
//   - NaN: every comparison against it is false, so `w.cost+cost > lim.MaxCost`
//     never trips — the request is allowed AND w.cost becomes NaN, which poisons
//     the window permanently (for a lifetime budget, Window == 0, forever).
//   - negative: refunds budget outright, raising the remaining allowance.
//
// Either way a caller controls its own budget, which is the thing the limiter
// exists to prevent.
func TestRepro16NonFiniteAndNegativeCostMustBeRejected(t *testing.T) {
	now := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	const agent = "release-reviewer"

	cases := []struct {
		name string
		cost float64
	}{
		{"NaN", math.NaN()},
		{"+Inf", math.Inf(1)},
		{"-Inf", math.Inf(-1)},
		{"negative", -1000000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewLimiter(map[string]Limits{agent: {MaxCost: 10}})

			// A poisoning charge must not be accepted.
			if d := l.Charge(agent, tc.cost, now); d.Allowed {
				t.Errorf("Charge(%v) was allowed; a non-finite or negative cost must be rejected", tc.cost)
			}

			// Whatever the decision, the budget must still work afterwards: a
			// charge past MaxCost has to be refused.
			if d := l.Charge(agent, 100, now); d.Allowed {
				t.Errorf("after a %v charge, a cost of 100 against MaxCost 10 was still allowed; "+
					"the budget has been destroyed for this window", tc.cost)
			}
		})
	}
}
