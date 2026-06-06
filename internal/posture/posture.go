// Package posture rolls the evidence ledger up into a current control-posture
// view: for each control, the latest observed result, how many times it has been
// observed, and how many of those observations were lapses. It is the day-to-day
// view for platform and quality teams, distinct from report's design-time
// coverage, which asks whether a control is mapped to a policy at all.
package posture

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// ControlPosture is one control's rolled-up posture across all its evidence.
type ControlPosture struct {
	ControlID    string
	Status       string // the latest observed result
	Records      int    // total evidence records observed for this control
	Lapses       int    // records observed as not-satisfied (stability signal)
	LastObserved time.Time
}

// Posture is the per-control rollup, one row per control seen in the evidence.
type Posture struct {
	Controls []ControlPosture
}

// Summarize rolls a set of evidence records up by control. The current status is
// the result of the latest record by observed-at (ties broken by record order,
// so the most recently appended wins). Controls are returned sorted by id.
func Summarize(records []evidence.Record) Posture {
	byControl := map[string]*ControlPosture{}
	for _, r := range records {
		cp := byControl[r.ControlID]
		if cp == nil {
			cp = &ControlPosture{ControlID: r.ControlID}
			byControl[r.ControlID] = cp
		}
		cp.Records++
		if r.Result != oscal.StatusSatisfied {
			cp.Lapses++
		}
		// Latest observation (or equal-time later append) sets current status.
		if cp.LastObserved.IsZero() || !r.ObservedAt.Before(cp.LastObserved) {
			cp.LastObserved = r.ObservedAt
			cp.Status = r.Result
		}
	}

	out := make([]ControlPosture, 0, len(byControl))
	for _, cp := range byControl {
		out = append(out, *cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControlID < out[j].ControlID })
	return Posture{Controls: out}
}

// NotSatisfied returns the controls whose current status is not satisfied - the
// live gaps a reviewer acts on.
func (p Posture) NotSatisfied() []ControlPosture {
	var gaps []ControlPosture
	for _, c := range p.Controls {
		if c.Status != oscal.StatusSatisfied {
			gaps = append(gaps, c)
		}
	}
	return gaps
}

// Render formats the posture as a plain-text table with a summary line.
func (p Posture) Render() string {
	idW := len("CONTROL")
	for _, c := range p.Controls {
		if len(c.ControlID) > idW {
			idW = len(c.ControlID)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-*s %-13s %-8s %-7s %s\n", idW, "CONTROL", "STATUS", "RECORDS", "LAPSES", "LAST OBSERVED")

	satisfied := 0
	for _, c := range p.Controls {
		if c.Status == oscal.StatusSatisfied {
			satisfied++
		}
		last := "-"
		if !c.LastObserved.IsZero() {
			last = c.LastObserved.Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "%-*s %-13s %-8d %-7d %s\n", idW, c.ControlID, c.Status, c.Records, c.Lapses, last)
	}

	b.WriteString("\n")
	b.WriteString(strconv.Itoa(len(p.Controls)) + " controls, ")
	b.WriteString(strconv.Itoa(satisfied) + " currently satisfied, ")
	b.WriteString(strconv.Itoa(len(p.Controls)-satisfied) + " with open gaps\n")
	return b.String()
}
