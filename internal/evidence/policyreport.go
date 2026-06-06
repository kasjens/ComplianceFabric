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
	var report struct {
		Results []struct {
			Policy    string     `json:"policy"`
			Result    string     `json:"result"`
			Resources []resource `json:"resources"`
			Timestamp struct {
				Seconds int64 `json:"seconds"`
			} `json:"timestamp"`
		} `json:"results"`
	}
	if err := json.Unmarshal(reportJSON, &report); err != nil {
		return nil, err
	}

	var records []Record
	for _, res := range report.Results {
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
		subject := ""
		if len(res.Resources) > 0 {
			r := res.Resources[0]
			if r.Namespace != "" {
				subject = fmt.Sprintf("ns/%s/%s/%s", r.Namespace, r.Kind, r.Name)
			} else {
				subject = fmt.Sprintf("%s/%s", r.Kind, r.Name)
			}
		}
		observedAt := time.Unix(res.Timestamp.Seconds, 0).UTC()
		for _, controlID := range controls {
			records = append(records, Record{
				ControlID:  controlID,
				Subject:    subject,
				Result:     status,
				ObservedAt: observedAt,
				Source:     "kyverno/" + res.Policy,
			})
		}
	}
	return records, nil
}
