// Package crosswalk reuses one framework's enforced controls to answer another
// framework's citations. This is the Phase 5 idea: a technical control the Fabric
// already enforces and evidences for, say, 21 CFR Part 11 also satisfies a DORA or
// NIS2 article, so the same enforcement answers a second sector with no new
// enforcement code. A crosswalk is the mapping from a target-sector citation to
// the anchor controls that already answer it; Apply rolls existing evidence up
// under those citations.
package crosswalk

import (
	"strings"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/posture"
)

// Crosswalk maps target-sector citations onto the controls that already answer
// them. It is an authored artifact, reviewed like any other control mapping.
type Crosswalk struct {
	Metadata oscal.Metadata `json:"metadata"`
	Mappings []Mapping      `json:"mappings"`
}

// Mapping declares that one target-sector citation (Control) is answered by a set
// of anchor controls the Fabric already enforces and evidences (SatisfiedBy). The
// target is satisfied only when every anchor is currently satisfied.
type Mapping struct {
	Control     string   `json:"control"`
	SatisfiedBy []string `json:"satisfied-by"`
}

// Apply rolls existing evidence up under the target-sector citations a crosswalk
// declares, producing one derived record per mapping in mapping order. A target
// citation is satisfied only when every anchor it maps to currently has satisfied
// evidence; a missing or not-satisfied anchor makes the target not-satisfied.
//
// The per-anchor "current status" is posture's: the latest observation by
// observed-at. Reusing posture.Summarize keeps one definition of a control's
// current state across the engine, so a crosswalk conclusion can never disagree
// with the posture view it is built from.
//
// A derived record carries no new raw evidence. Its source names the anchor
// controls that answer it, so a reviewer can trace the second-framework citation
// straight back to the single enforced control behind it.
func Apply(records []evidence.Record, cw Crosswalk) []evidence.Record {
	status := map[string]posture.ControlPosture{}
	for _, cp := range posture.Summarize(records).Controls {
		status[cp.ControlID] = cp
	}

	derived := make([]evidence.Record, 0, len(cw.Mappings))
	for _, m := range cw.Mappings {
		// A citation answered by NO anchors is not satisfied - it is unevidenced.
		// Seeding the result as satisfied and relying on the loop to disprove it
		// means a mapping with an empty (or misspelled, so absent) satisfied-by
		// list claims compliance by vacuity, as of a zero timestamp.
		result := oscal.StatusSatisfied
		if len(m.SatisfiedBy) == 0 {
			result = oscal.StatusNotSatisfied
		}
		var latest time.Time
		for _, anchor := range m.SatisfiedBy {
			cp, ok := status[anchor]
			if !ok || cp.Status != oscal.StatusSatisfied {
				result = oscal.StatusNotSatisfied
			}
			if ok && cp.LastObserved.After(latest) {
				latest = cp.LastObserved
			}
		}
		derived = append(derived, evidence.Record{
			ControlID:  m.Control,
			Subject:    "crosswalk/" + m.Control,
			Result:     result,
			ObservedAt: latest,
			Source:     "crosswalk/" + strings.Join(m.SatisfiedBy, ","),
		})
	}
	return derived
}
