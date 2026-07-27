package evidence

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// FromPolicyReport turns a Kyverno PolicyReport (wgpolicyk8s.io/v1alpha2, as
// emitted by `kubectl get policyreport -o json`) into evidence records keyed to
// the controls the reported policies enforce. policyControls maps a policy name
// to the control ids it annotates with fabric.control-id.
//
// It accepts either a single PolicyReport object or the List wrapper kubectl
// returns when a namespace holds more than one report (Kyverno writes one report
// per resource); a List's items are flattened and their results aggregated.
//
// A pass result is satisfied; fail, error, and warn are not-satisfied; skip
// produces no evidence (the policy did not apply to the resource). Results whose
// policy is not mapped to a control are ignored. A result is fanned out to one
// record per control the policy maps to, in the order the controls are listed.
func FromPolicyReport(reportJSON []byte, policyControls map[string][]string) ([]Record, error) {
	type resource struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	type result struct {
		Policy    string     `json:"policy"`
		Result    string     `json:"result"`
		Resources []resource `json:"resources"`
		Timestamp struct {
			Seconds int64 `json:"seconds"`
		} `json:"timestamp"`
	}
	type doc struct {
		Scope   *resource `json:"scope"`
		Results []result  `json:"results"`
		Items   []struct {
			Scope   *resource `json:"scope"`
			Results []result  `json:"results"`
		} `json:"items"`
	}
	var parsed doc
	if err := json.Unmarshal(reportJSON, &parsed); err != nil {
		return nil, err
	}

	// Stands in for the observation time of any result whose own timestamp is
	// absent. Read once so every imputed record in a report shares one value.
	collectedAt := time.Now().UTC()

	// Pair each result with the scope of its enclosing report. Kyverno's
	// background reports carry the audited resource at the report level (scope)
	// rather than per result.
	type scopedResult struct {
		res   result
		scope *resource
	}
	var results []scopedResult
	for _, res := range parsed.Results {
		results = append(results, scopedResult{res, parsed.Scope})
	}
	for _, item := range parsed.Items {
		for _, res := range item.Results {
			results = append(results, scopedResult{res, item.Scope})
		}
	}

	var records []Record
	for _, sr := range results {
		res := sr.res
		if res.Result == "skip" {
			continue
		}
		controls := policyControls[res.Policy]
		if len(controls) == 0 {
			continue
		}
		status := oscal.StatusNotSatisfied
		if res.Result == "pass" {
			status = oscal.StatusSatisfied
		}
		var subj *resource
		if len(res.Resources) > 0 {
			subj = &res.Resources[0]
		} else if sr.scope != nil {
			subj = sr.scope
		}
		subject := ""
		if subj != nil {
			if subj.Namespace != "" {
				subject = fmt.Sprintf("ns/%s/%s/%s", subj.Namespace, subj.Kind, subj.Name)
			} else {
				subject = fmt.Sprintf("%s/%s", subj.Kind, subj.Name)
			}
		}
		// The Kyverno timestamp is optional. An absent one decodes to zero
		// seconds, and time.Unix(0,0) is 1970 — a value that is not IsZero(), so
		// nothing downstream could tell an imputed time from a real one. It sorted
		// to the front of every trend and lost every latest-wins comparison,
		// freezing a stale green. Substitute collection time and mark the record,
		// so the imputation is visible rather than asserted as fact.
		observedAt := time.Unix(res.Timestamp.Seconds, 0).UTC()
		imputed := false
		if res.Timestamp.Seconds <= 0 {
			observedAt = collectedAt
			imputed = true
		}
		for _, controlID := range controls {
			records = append(records, Record{
				ControlID:         controlID,
				Subject:           subject,
				Result:            status,
				ObservedAt:        observedAt,
				ObservedAtImputed: imputed,
				Source:            "kyverno/" + res.Policy,
			})
		}
	}
	return records, nil
}
