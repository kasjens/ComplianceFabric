// Package assess turns a control bundle into an OSCAL assessment-results
// document. This is a design-time assessment: a control selected by a profile is
// "satisfied" when a component definition maps it to at least one policy, and
// "not-satisfied" when it is in scope but has no enforcement behind it.
package assess

import (
	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/report"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

// Assess produces an OSCAL assessment-results document covering every control a
// profile selects. Controls not in scope are omitted.
func Assess(b validate.Bundle) oscal.AssessmentResults {
	var findings []oscal.AssessmentFinding
	for _, c := range report.Coverage(b) {
		if !c.Selected {
			continue
		}
		if len(c.PolicyIDs) > 0 {
			findings = append(findings, oscal.AssessmentFinding{
				ControlID: c.ControlID,
				Status:    oscal.StatusSatisfied,
				Statement: "control is mapped to enforcement policy",
			})
		} else {
			findings = append(findings, oscal.AssessmentFinding{
				ControlID: c.ControlID,
				Status:    oscal.StatusNotSatisfied,
				Statement: "control is in scope but no policy implements it",
			})
		}
	}

	return oscal.AssessmentResults{
		Metadata: oscal.Metadata{
			Title:   "Design-time control coverage assessment",
			Version: "0.1.0",
		},
		Results: []oscal.Result{{
			Title:    "Profile-selected control coverage",
			Findings: findings,
		}},
	}
}
