package evidence

import (
	"testing"
	"time"
)

// argoApplicationsJSON is `kubectl get applications -o json`: a List of Argo CD
// Applications, one Synced (qualified state intact) and one OutOfSync (drift).
const argoApplicationsJSON = `{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "metadata": { "name": "mes" },
      "status": {
        "sync": { "status": "Synced" },
        "health": { "status": "Healthy" },
        "reconciledAt": "2026-06-06T08:14:00Z"
      }
    },
    {
      "metadata": { "name": "historian" },
      "status": {
        "sync": { "status": "OutOfSync" },
        "health": { "status": "Degraded" },
        "reconciledAt": "2026-06-06T08:14:00Z"
      }
    }
  ]
}`

func TestFromArgoApplicationsMapsSyncStatus(t *testing.T) {
	records, err := FromArgoApplications([]byte(argoApplicationsJSON), "annex11-11-periodic-evaluation")
	if err != nil {
		t.Fatalf("FromArgoApplications: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("want a record per application, got %d", len(records))
	}

	synced := records[0]
	if synced.ControlID != "annex11-11-periodic-evaluation" {
		t.Errorf("control id = %q", synced.ControlID)
	}
	if synced.Result != "satisfied" {
		t.Errorf("Synced app result = %q, want satisfied", synced.Result)
	}
	if synced.Subject != "app/mes" {
		t.Errorf("subject = %q, want app/mes", synced.Subject)
	}
	if synced.Source != "argocd/mes" {
		t.Errorf("source = %q, want argocd/mes", synced.Source)
	}
	want := time.Date(2026, 6, 6, 8, 14, 0, 0, time.UTC)
	if !synced.ObservedAt.Equal(want) {
		t.Errorf("observed-at = %v, want %v", synced.ObservedAt, want)
	}
	if synced.Change != nil {
		t.Errorf("drift record should not embed a change record")
	}

	drifted := records[1]
	if drifted.Result != "not-satisfied" {
		t.Errorf("OutOfSync app result = %q, want not-satisfied", drifted.Result)
	}
	if drifted.Subject != "app/historian" {
		t.Errorf("subject = %q, want app/historian", drifted.Subject)
	}
}

func TestFromArgoApplicationsEmptyForNoApps(t *testing.T) {
	records, err := FromArgoApplications([]byte(`{"items":[]}`), "annex11-11-periodic-evaluation")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Errorf("want no records for no applications, got %d", len(records))
	}
}
