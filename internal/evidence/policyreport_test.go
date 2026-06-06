package evidence

import (
	"testing"
	"time"
)

// policyReportJSON is a Kyverno PolicyReport (wgpolicyk8s.io/v1alpha2) as emitted
// by `kubectl get policyreport -o json`: a pass and a fail against two policies,
// plus a skip that produces no evidence.
const policyReportJSON = `{
  "apiVersion": "wgpolicyk8s.io/v1alpha2",
  "kind": "PolicyReport",
  "metadata": { "namespace": "mes", "name": "cpol-report" },
  "results": [
    {
      "policy": "require-run-as-non-root",
      "rule": "run-as-non-root",
      "result": "pass",
      "resources": [{ "kind": "Pod", "namespace": "mes", "name": "mes-7d9f" }],
      "timestamp": { "seconds": 1717661640, "nanos": 0 }
    },
    {
      "policy": "require-audit-logging-annotations",
      "rule": "require-audit-logging",
      "result": "fail",
      "resources": [{ "kind": "Pod", "namespace": "mes", "name": "mes-legacy" }],
      "timestamp": { "seconds": 1717661640, "nanos": 0 }
    },
    {
      "policy": "require-run-as-non-root",
      "rule": "run-as-non-root",
      "result": "skip",
      "resources": [{ "kind": "Service", "namespace": "mes", "name": "mes-svc" }],
      "timestamp": { "seconds": 1717661640, "nanos": 0 }
    }
  ]
}`

func policyControls() map[string][]string {
	return map[string][]string{
		"require-run-as-non-root":           {"annex11-12-1-access-control"},
		"require-audit-logging-annotations": {"annex11-9-audit-trail"},
	}
}

func TestFromPolicyReportMapsResultsToControls(t *testing.T) {
	records, err := FromPolicyReport([]byte(policyReportJSON), policyControls())
	if err != nil {
		t.Fatalf("FromPolicyReport: %v", err)
	}
	// pass + fail produce records; skip does not.
	if len(records) != 2 {
		t.Fatalf("want 2 records (pass, fail; skip omitted), got %d: %+v", len(records), records)
	}

	pass := records[0]
	if pass.ControlID != "annex11-12-1-access-control" {
		t.Errorf("pass control id = %q", pass.ControlID)
	}
	if pass.Result != "satisfied" {
		t.Errorf("pass result = %q, want satisfied", pass.Result)
	}
	if pass.Source != "kyverno/require-run-as-non-root" {
		t.Errorf("pass source = %q", pass.Source)
	}
	if pass.Subject != "ns/mes/Pod/mes-7d9f" {
		t.Errorf("pass subject = %q", pass.Subject)
	}
	want := time.Unix(1717661640, 0).UTC()
	if !pass.ObservedAt.Equal(want) {
		t.Errorf("observed-at = %v, want %v", pass.ObservedAt, want)
	}
	if pass.Change != nil {
		t.Errorf("policy-report record should not embed a change record, got %+v", pass.Change)
	}

	fail := records[1]
	if fail.ControlID != "annex11-9-audit-trail" {
		t.Errorf("fail control id = %q", fail.ControlID)
	}
	if fail.Result != "not-satisfied" {
		t.Errorf("fail result = %q, want not-satisfied", fail.Result)
	}
}

// policyReportListJSON is what `kubectl get policyreport -o json` returns when
// the namespace holds more than one report: a List wrapper with items[]. Kyverno
// generates one PolicyReport per resource, so this is the common live shape.
const policyReportListJSON = `{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "apiVersion": "wgpolicyk8s.io/v1alpha2",
      "kind": "PolicyReport",
      "metadata": { "namespace": "e2e", "name": "rep-1" },
      "results": [
        {
          "policy": "require-run-as-non-root",
          "rule": "run-as-non-root",
          "result": "pass",
          "resources": [{ "kind": "Pod", "namespace": "e2e", "name": "compliant" }],
          "timestamp": { "seconds": 1717661640, "nanos": 0 }
        }
      ]
    },
    {
      "apiVersion": "wgpolicyk8s.io/v1alpha2",
      "kind": "PolicyReport",
      "metadata": { "namespace": "e2e", "name": "rep-2" },
      "results": [
        {
          "policy": "require-audit-logging-annotations",
          "rule": "require-audit-logging",
          "result": "pass",
          "resources": [{ "kind": "Pod", "namespace": "e2e", "name": "compliant" }],
          "timestamp": { "seconds": 1717661640, "nanos": 0 }
        }
      ]
    }
  ]
}`

func TestFromPolicyReportHandlesListShape(t *testing.T) {
	records, err := FromPolicyReport([]byte(policyReportListJSON), policyControls())
	if err != nil {
		t.Fatalf("FromPolicyReport: %v", err)
	}
	// Both items' results aggregate; each maps to its control.
	if len(records) != 2 {
		t.Fatalf("want 2 records across the list items, got %d: %+v", len(records), records)
	}
	if records[0].ControlID != "annex11-12-1-access-control" {
		t.Errorf("first control id = %q", records[0].ControlID)
	}
	if records[1].ControlID != "annex11-9-audit-trail" {
		t.Errorf("second control id = %q", records[1].ControlID)
	}
	for _, r := range records {
		if r.Result != "satisfied" {
			t.Errorf("record %q result = %q, want satisfied", r.ControlID, r.Result)
		}
	}
}

// liveReportListJSON mirrors a real Kyverno background report: the audited
// resource is carried in the item-level `scope`, and the results have no
// per-result `resources` array. The subject must still identify the workload.
const liveReportListJSON = `{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "kind": "PolicyReport",
      "metadata": { "namespace": "e2e", "name": "rep-1" },
      "scope": { "kind": "Pod", "namespace": "e2e", "name": "compliant" },
      "results": [
        {
          "policy": "require-run-as-non-root",
          "rule": "run-as-non-root",
          "result": "pass",
          "timestamp": { "seconds": 1717661640, "nanos": 0 }
        }
      ]
    }
  ]
}`

func TestFromPolicyReportDerivesSubjectFromScope(t *testing.T) {
	records, err := FromPolicyReport([]byte(liveReportListJSON), policyControls())
	if err != nil {
		t.Fatalf("FromPolicyReport: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(records), records)
	}
	if records[0].Subject != "ns/e2e/Pod/compliant" {
		t.Errorf("subject = %q, want ns/e2e/Pod/compliant (from item scope)", records[0].Subject)
	}
}

func TestFromPolicyReportSkipsUnmappedPolicy(t *testing.T) {
	// A report referencing a policy with no control mapping yields no records.
	report := `{"results":[{"policy":"some-other-policy","result":"pass",
	  "resources":[{"kind":"Pod","namespace":"mes","name":"x"}],
	  "timestamp":{"seconds":1717661640}}]}`
	records, err := FromPolicyReport([]byte(report), policyControls())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Errorf("want no records for an unmapped policy, got %d", len(records))
	}
}

func TestFromPolicyReportFanOutToMultipleControls(t *testing.T) {
	report := `{"results":[{"policy":"multi","result":"fail",
	  "resources":[{"kind":"Pod","namespace":"mes","name":"x"}],
	  "timestamp":{"seconds":1717661640}}]}`
	controls := map[string][]string{"multi": {"control-a", "control-b"}}
	records, err := FromPolicyReport([]byte(report), controls)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("want one record per mapped control, got %d", len(records))
	}
	if records[0].ControlID != "control-a" || records[1].ControlID != "control-b" {
		t.Errorf("control fan-out wrong: %q, %q", records[0].ControlID, records[1].ControlID)
	}
}
