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
	ControlID string
	// Status is the control's current result rolled up across every subject,
	// worst-status-wins: satisfied only when every subject under it is satisfied.
	// It is NOT simply the latest record's result — one subject passing cannot
	// clear another subject that is failing.
	Status       string
	Records      int // total evidence records observed for this control
	Lapses       int // records observed as not-satisfied (stability signal)
	LastObserved time.Time
	// Subjects carries the per-subject detail behind Status, in first-seen order,
	// so a reviewer can see WHICH subject is failing rather than only that the
	// control is.
	Subjects []SubjectPosture
}

// SubjectPosture is one subject's current status under a control.
type SubjectPosture struct {
	Subject      string
	Status       string
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
	type subjectState struct {
		id           string
		status       string
		lastObserved time.Time
		seenAt       int
	}

	byControl := map[string]*ControlPosture{}
	subjects := map[string]map[string]*subjectState{}

	for i, r := range records {
		cp := byControl[r.ControlID]
		if cp == nil {
			cp = &ControlPosture{ControlID: r.ControlID}
			byControl[r.ControlID] = cp
			subjects[r.ControlID] = map[string]*subjectState{}
		}
		cp.Records++
		if r.Result != oscal.StatusSatisfied {
			cp.Lapses++
		}
		if r.ObservedAt.After(cp.LastObserved) {
			cp.LastObserved = r.ObservedAt
		}

		// Track the latest status PER SUBJECT. Keying only on the control let one
		// subject's later, passing observation overwrite another subject's
		// failure, so a drifted app or a blocked interaction disappeared from the
		// control's status and from NotSatisfied entirely.
		st := subjects[r.ControlID][r.Subject]
		if st == nil {
			st = &subjectState{id: r.Subject, seenAt: i}
			subjects[r.ControlID][r.Subject] = st
		}
		// A record whose timestamp is missing or epoch carries no usable time, so
		// ledger append order decides instead. Comparing it as a real 1970
		// observation made it lose to any prior record, which silently preserved a
		// stale green when the newest evidence said the control had failed.
		if unusableTime(st.lastObserved) || unusableTime(r.ObservedAt) || !r.ObservedAt.Before(st.lastObserved) {
			st.lastObserved = r.ObservedAt
			st.status = r.Result
		}
	}

	out := make([]ControlPosture, 0, len(byControl))
	for id, cp := range byControl {
		// Roll the per-subject statuses up worst-status-wins: a control is only
		// satisfied when every subject under it is.
		states := make([]*subjectState, 0, len(subjects[id]))
		for _, st := range subjects[id] {
			states = append(states, st)
		}
		sort.Slice(states, func(i, j int) bool { return states[i].seenAt < states[j].seenAt })

		cp.Status = oscal.StatusSatisfied
		cp.Subjects = make([]SubjectPosture, 0, len(states))
		for _, st := range states {
			if st.status != oscal.StatusSatisfied {
				cp.Status = st.status
			}
			cp.Subjects = append(cp.Subjects, SubjectPosture{
				Subject:      st.id,
				Status:       st.status,
				LastObserved: st.lastObserved,
			})
		}
		out = append(out, *cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControlID < out[j].ControlID })
	return Posture{Controls: out}
}

// unusableTime reports whether a timestamp carries no real observation time: the
// zero value, or the Unix epoch that an absent optional timestamp decodes to.
func unusableTime(t time.Time) bool {
	return t.IsZero() || t.Unix() <= 0
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
