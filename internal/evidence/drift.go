package evidence

import (
	"encoding/json"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// FromArgoApplications turns Argo CD Application status (as emitted by
// `kubectl get applications -o json`) into drift evidence records keyed to the
// given control. A Synced application means the running state still matches the
// validated state held in Git (satisfied); anything else - OutOfSync, Unknown -
// is drift away from the qualified state (not-satisfied). One record is produced
// per application.
func FromArgoApplications(appsJSON []byte, controlID string) ([]Record, error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Sync struct {
					Status string `json:"status"`
				} `json:"sync"`
				ReconciledAt time.Time `json:"reconciledAt"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(appsJSON, &list); err != nil {
		return nil, err
	}

	var records []Record
	for _, app := range list.Items {
		status := oscal.StatusNotSatisfied
		if app.Status.Sync.Status == "Synced" {
			status = oscal.StatusSatisfied
		}
		records = append(records, Record{
			ControlID:  controlID,
			Subject:    "app/" + app.Metadata.Name,
			Result:     status,
			ObservedAt: app.Status.ReconciledAt.UTC(),
			Source:     "argocd/" + app.Metadata.Name,
		})
	}
	return records, nil
}
