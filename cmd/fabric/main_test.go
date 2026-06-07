package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
)

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// repoControlsDir resolves <repo>/controls from this test file's location so the
// test does not depend on the working directory.
func repoControlsDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "controls")
}

func TestValidateRealControlsIsClean(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"validate", repoControlsDir(t)}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for the shipped controls, got %d. output:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "no findings") {
		t.Errorf("expected a clean-result message, got:\n%s", out.String())
	}
}

func TestValidateReportsFindingsAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "catalogs", "c.json"), `{"id":"x","controls":[{"id":"a"}]}`)
	writeFixture(t, filepath.Join(dir, "profiles", "p.json"),
		`{"imports":[{"href":"x","include-controls":["does-not-exist"]}]}`)

	var out bytes.Buffer
	code := run([]string{"validate", dir}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 when findings exist, got %d", code)
	}
	if !strings.Contains(out.String(), "unresolved-control") {
		t.Errorf("expected unresolved-control in output, got:\n%s", out.String())
	}
}

func TestReportRendersRealControls(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"report", repoControlsDir(t)}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for report, got %d. output:\n%s", code, out.String())
	}
	for _, want := range []string{"annex11-9-audit-trail", "cfr-part-11-10e-audit-trail", "selected"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report output missing %q:\n%s", want, out.String())
		}
	}
}

func TestAssessEmitsValidOSCALJSON(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"assess", repoControlsDir(t)}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for assess, got %d. output:\n%s", code, out.String())
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("assess output is not valid JSON:\n%s", out.String())
	}
	for _, want := range []string{"annex11-9-audit-trail", "satisfied", "control-id"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("assess output missing %q:\n%s", want, out.String())
		}
	}
}

func TestAssessStrictExitsNonZeroOnGaps(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "catalogs", "c.json"),
		`{"id":"x","controls":[{"id":"a","title":"A"}]}`)
	writeFixture(t, filepath.Join(dir, "profiles", "p.json"),
		`{"imports":[{"href":"x","include-controls":["a"]}]}`)

	var out bytes.Buffer
	code := run([]string{"assess", "--strict", dir}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 when in-scope control is unenforced, got %d", code)
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("strict assess should still emit valid JSON:\n%s", out.String())
	}
}

func TestAssessStrictExitsZeroWhenAllSatisfied(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"assess", "--strict", repoControlsDir(t)}, &out); code != 0 {
		t.Fatalf("expected exit 0 for fully-covered controls, got %d:\n%s", code, out.String())
	}
}

// repoDir resolves <repo>/<name> from this test file's location.
func repoDir(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", name)
}

func TestPoliciesPassesForShippedLibrary(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"policies", repoControlsDir(t), repoDir(t, "policies")}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for the shipped policy library, got %d. output:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "no findings") {
		t.Errorf("expected a clean-result message, got:\n%s", out.String())
	}
}

func TestPoliciesReportsMissingPolicyAndExitsNonZero(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"policies", repoControlsDir(t), t.TempDir()}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 when policy files are absent, got %d", code)
	}
	if !strings.Contains(out.String(), "missing-policy") {
		t.Errorf("expected missing-policy in output, got:\n%s", out.String())
	}
}

func TestGenerateComposesSelectedPoliciesForShippedControls(t *testing.T) {
	out := t.TempDir()
	var buf bytes.Buffer
	code := run([]string{"generate", repoControlsDir(t), repoDir(t, "policies"), out}, &buf)
	if code != 0 {
		t.Fatalf("expected exit 0 for generate, got %d. output:\n%s", code, buf.String())
	}
	// The pharma MES baseline selects audit-trail and access-control controls,
	// whose Kyverno checks include require-audit-logging-annotations.
	composed := filepath.Join(out, "kyverno", "require-audit-logging-annotations.yaml")
	if _, err := os.Stat(composed); err != nil {
		t.Fatalf("expected composed policy at %s: %v", composed, err)
	}
	// A control the baseline does not select must not be composed.
	if _, err := os.Stat(filepath.Join(out, "kyverno", "require-encryption-at-rest.yaml")); err == nil {
		t.Error("composed a policy for an unselected control")
	}
}

func TestGenerateRequiresThreeArgs(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"generate", repoControlsDir(t)}, &buf); code != 2 {
		t.Fatalf("expected exit 2 for missing generate args, got %d", code)
	}
}

func TestAssessCoversChangeControlAsSatisfied(t *testing.T) {
	var out bytes.Buffer
	// --strict exits 0 only if every selected control is satisfied, so a clean
	// exit plus the control's presence proves the change-control control is
	// covered by its (non-Kyverno) GitOps component.
	code := run([]string{"assess", "--strict", repoControlsDir(t)}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 with change-control covered, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "annex11-10-change-control") {
		t.Errorf("assess output missing annex11-10-change-control:\n%s", out.String())
	}
}

func TestEvidenceValidChangeExitsZero(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{
  "number": 42, "state": "MERGED", "author": {"login": "kasjens"},
  "mergedAt": "2026-06-05T14:30:00Z", "mergeCommit": {"oid": "32fa9af"},
  "reviews": [{"author": {"login": "rev"}, "state": "APPROVED"}]
}`)

	var out bytes.Buffer
	code := run([]string{"evidence", pr}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for a valid authorized change, got %d. output:\n%s", code, out.String())
	}
	for _, want := range []string{"kasjens", "32fa9af"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("evidence output missing %q:\n%s", want, out.String())
		}
	}
}

func TestEvidenceFlagsInvalidChangeAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{"number": 7, "state": "OPEN", "author": {"login": "kasjens"}, "reviews": []}`)

	var out bytes.Buffer
	code := run([]string{"evidence", pr}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 for an unmerged, unapproved change, got %d", code)
	}
	if !strings.Contains(out.String(), "no approval") {
		t.Errorf("expected a no-approval finding, got:\n%s", out.String())
	}
}

func TestEvidenceRequiresOneArg(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"evidence"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing evidence arg, got %d", code)
	}
}

func TestEvidenceWithControlIdEmitsJSONRecord(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{
  "number": 42, "state": "MERGED", "author": {"login": "kasjens"},
  "mergedAt": "2026-06-05T14:30:00Z", "mergeCommit": {"oid": "32fa9af"},
  "reviews": [{"author": {"login": "rev"}, "state": "APPROVED"}]
}`)

	var out bytes.Buffer
	code := run([]string{"evidence", pr, "annex11-10-change-control"}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for a valid change keyed to a control, got %d:\n%s", code, out.String())
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("expected a JSON evidence record, got:\n%s", out.String())
	}
	for _, want := range []string{"control-id", "annex11-10-change-control", "satisfied"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("evidence record missing %q:\n%s", want, out.String())
		}
	}
}

func TestEvidenceWithControlIdFlaggedExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{"number": 7, "state": "OPEN", "author": {"login": "kasjens"}, "reviews": []}`)

	var out bytes.Buffer
	code := run([]string{"evidence", pr, "annex11-10-change-control"}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 for a flagged change, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "not-satisfied") {
		t.Errorf("expected a not-satisfied record, got:\n%s", out.String())
	}
}

func TestEvidenceAppendsToLedgerAndVerifies(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{
  "number": 42, "state": "MERGED", "author": {"login": "kasjens"},
  "mergedAt": "2026-06-05T14:30:00Z", "mergeCommit": {"oid": "32fa9af"},
  "reviews": [{"author": {"login": "rev"}, "state": "APPROVED"}]
}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	if code := run([]string{"evidence", pr, "annex11-10-change-control", "--ledger", led}, &out); code != 0 {
		t.Fatalf("expected exit 0 appending a valid change, got %d:\n%s", code, out.String())
	}
	data, err := os.ReadFile(led)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	if !strings.Contains(string(data), "annex11-10-change-control") {
		t.Errorf("ledger missing the control id:\n%s", string(data))
	}

	var vout bytes.Buffer
	if code := run([]string{"ledger", "verify", led}, &vout); code != 0 {
		t.Fatalf("expected exit 0 verifying an intact ledger, got %d:\n%s", code, vout.String())
	}
}

func TestLedgerVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{
  "number": 42, "state": "MERGED", "author": {"login": "kasjens"},
  "mergedAt": "2026-06-05T14:30:00Z", "mergeCommit": {"oid": "32fa9af"},
  "reviews": [{"author": {"login": "rev"}, "state": "APPROVED"}]
}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	if code := run([]string{"evidence", pr, "annex11-10-change-control", "--ledger", led}, &out); code != 0 {
		t.Fatalf("append failed: %d\n%s", code, out.String())
	}
	data, err := os.ReadFile(led)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), "satisfied", "not-satisfied", 1)
	if err := os.WriteFile(led, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	var vout bytes.Buffer
	if code := run([]string{"ledger", "verify", led}, &vout); code != 1 {
		t.Fatalf("expected exit 1 for a tampered ledger, got %d:\n%s", code, vout.String())
	}
}

func TestLedgerRequiresVerifyAndPath(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"ledger"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing ledger args, got %d", code)
	}
}

func TestLedgerAssessEmitsOSCALResults(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{
  "number": 42, "state": "MERGED", "author": {"login": "kasjens"},
  "mergedAt": "2026-06-05T14:30:00Z", "mergeCommit": {"oid": "32fa9af"},
  "reviews": [{"author": {"login": "rev"}, "state": "APPROVED"}]
}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	if code := run([]string{"evidence", pr, "annex11-10-change-control", "--ledger", led}, &out); code != 0 {
		t.Fatalf("append failed: %d\n%s", code, out.String())
	}

	var aout bytes.Buffer
	if code := run([]string{"ledger", "assess", led}, &aout); code != 0 {
		t.Fatalf("expected exit 0 assessing a satisfied ledger, got %d:\n%s", code, aout.String())
	}
	var ar struct {
		Results []struct {
			Findings []struct {
				ControlID string `json:"control-id"`
				Status    string `json:"status"`
			} `json:"findings"`
		} `json:"results"`
	}
	if err := json.Unmarshal(aout.Bytes(), &ar); err != nil {
		t.Fatalf("output is not OSCAL assessment-results JSON: %v\n%s", err, aout.String())
	}
	if len(ar.Results) != 1 || len(ar.Results[0].Findings) != 1 {
		t.Fatalf("want one finding, got %+v", ar.Results)
	}
	if ar.Results[0].Findings[0].ControlID != "annex11-10-change-control" {
		t.Errorf("finding control id = %q", ar.Results[0].Findings[0].ControlID)
	}
	if ar.Results[0].Findings[0].Status != "satisfied" {
		t.Errorf("finding status = %q, want satisfied", ar.Results[0].Findings[0].Status)
	}
}

func TestLedgerPostureRendersRollup(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{
  "number": 42, "state": "MERGED", "author": {"login": "kasjens"},
  "mergedAt": "2026-06-05T14:30:00Z", "mergeCommit": {"oid": "32fa9af"},
  "reviews": [{"author": {"login": "rev"}, "state": "APPROVED"}]
}`)
	led := filepath.Join(dir, "ledger.jsonl")
	if code := run([]string{"evidence", pr, "annex11-10-change-control", "--ledger", led}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("append failed: %d", code)
	}

	var out bytes.Buffer
	if code := run([]string{"ledger", "posture", led}, &out); code != 0 {
		t.Fatalf("expected exit 0 for an all-satisfied posture, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "annex11-10-change-control") {
		t.Errorf("posture missing the control:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "currently satisfied") {
		t.Errorf("posture missing the summary line:\n%s", out.String())
	}
}

func TestLedgerPostureExitsNonZeroOnOpenGap(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{
  "number": 7, "state": "OPEN", "author": {"login": "kasjens"},
  "mergedAt": null, "mergeCommit": null, "reviews": []
}`)
	led := filepath.Join(dir, "ledger.jsonl")
	if code := run([]string{"evidence", pr, "annex11-10-change-control", "--ledger", led}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("expected exit 1 recording a flagged change, got %d", code)
	}

	var out bytes.Buffer
	if code := run([]string{"ledger", "posture", led}, &out); code != 1 {
		t.Fatalf("expected exit 1 when a control has an open gap, got %d:\n%s", code, out.String())
	}
}

func TestLedgerAssessExitsNonZeroOnNotSatisfied(t *testing.T) {
	dir := t.TempDir()
	pr := filepath.Join(dir, "pr.json")
	writeFixture(t, pr, `{
  "number": 7, "state": "OPEN", "author": {"login": "kasjens"},
  "mergedAt": null, "mergeCommit": null, "reviews": []
}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	// An unmerged change is flagged (exit 1) but still recorded to the ledger.
	if code := run([]string{"evidence", pr, "annex11-10-change-control", "--ledger", led}, &out); code != 1 {
		t.Fatalf("expected exit 1 for a flagged change, got %d\n%s", code, out.String())
	}

	var aout bytes.Buffer
	if code := run([]string{"ledger", "assess", led}, &aout); code != 1 {
		t.Fatalf("expected exit 1 when the ledger has a not-satisfied finding, got %d:\n%s", code, aout.String())
	}
}

// writePolicyFixture writes a minimal Kyverno policy carrying a control-id
// annotation under <dir>/kyverno/<name>.yaml.
func writePolicyFixture(t *testing.T, dir, name, controlID string) {
	t.Helper()
	body := "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: " + name +
		"\n  annotations:\n    fabric.control-id: " + controlID + "\n"
	writeFixture(t, filepath.Join(dir, "kyverno", name+".yaml"), body)
}

func TestPolicyReportProducesEvidenceAndAppendsToLedger(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policies")
	writePolicyFixture(t, pol, "require-run-as-non-root", "annex11-12-1-access-control")
	writePolicyFixture(t, pol, "require-audit-logging-annotations", "annex11-9-audit-trail")

	report := filepath.Join(dir, "report.json")
	writeFixture(t, report, `{"results":[
	  {"policy":"require-run-as-non-root","result":"pass",
	   "resources":[{"kind":"Pod","namespace":"mes","name":"ok"}],"timestamp":{"seconds":1717661640}},
	  {"policy":"require-audit-logging-annotations","result":"fail",
	   "resources":[{"kind":"Pod","namespace":"mes","name":"bad"}],"timestamp":{"seconds":1717661640}}
	]}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	// A failing result is recorded but flags the run, so the command exits 1.
	if code := run([]string{"policy-report", report, pol, "--ledger", led}, &out); code != 1 {
		t.Fatalf("expected exit 1 when a result fails, got %d:\n%s", code, out.String())
	}

	var records []struct {
		ControlID string `json:"control-id"`
		Result    string `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("output is not a JSON array of records: %v\n%s", err, out.String())
	}
	if len(records) != 2 {
		t.Fatalf("want 2 evidence records, got %d", len(records))
	}

	data, err := os.ReadFile(led)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	if !strings.Contains(string(data), "annex11-9-audit-trail") {
		t.Errorf("ledger missing the failing control's record:\n%s", string(data))
	}
}

func TestPolicyReportAllPassExitsZero(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policies")
	writePolicyFixture(t, pol, "require-run-as-non-root", "annex11-12-1-access-control")
	report := filepath.Join(dir, "report.json")
	writeFixture(t, report, `{"results":[
	  {"policy":"require-run-as-non-root","result":"pass",
	   "resources":[{"kind":"Pod","namespace":"mes","name":"ok"}],"timestamp":{"seconds":1717661640}}
	]}`)

	var out bytes.Buffer
	if code := run([]string{"policy-report", report, pol}, &out); code != 0 {
		t.Fatalf("expected exit 0 when all results pass, got %d:\n%s", code, out.String())
	}
}

func TestPolicyReportRequiresTwoPositionalArgs(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"policy-report", "only-one-arg"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}

func TestDriftProducesEvidenceAndAppendsToLedger(t *testing.T) {
	dir := t.TempDir()
	apps := filepath.Join(dir, "apps.json")
	writeFixture(t, apps, `{"items":[
	  {"metadata":{"name":"mes"},"status":{"sync":{"status":"Synced"},"reconciledAt":"2026-06-06T08:14:00Z"}},
	  {"metadata":{"name":"historian"},"status":{"sync":{"status":"OutOfSync"},"reconciledAt":"2026-06-06T08:14:00Z"}}
	]}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	// One application has drifted, so the run is flagged (exit 1).
	if code := run([]string{"drift", apps, "annex11-11-periodic-evaluation", "--ledger", led}, &out); code != 1 {
		t.Fatalf("expected exit 1 when an app is OutOfSync, got %d:\n%s", code, out.String())
	}

	var records []struct {
		ControlID string `json:"control-id"`
		Subject   string `json:"subject"`
		Result    string `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("output is not a JSON array of records: %v\n%s", err, out.String())
	}
	if len(records) != 2 {
		t.Fatalf("want 2 drift records, got %d", len(records))
	}

	data, err := os.ReadFile(led)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	if !strings.Contains(string(data), "app/historian") {
		t.Errorf("ledger missing the drifted app's record:\n%s", string(data))
	}
}

func TestDriftAllSyncedExitsZero(t *testing.T) {
	dir := t.TempDir()
	apps := filepath.Join(dir, "apps.json")
	writeFixture(t, apps, `{"items":[
	  {"metadata":{"name":"mes"},"status":{"sync":{"status":"Synced"},"reconciledAt":"2026-06-06T08:14:00Z"}}
	]}`)

	var out bytes.Buffer
	if code := run([]string{"drift", apps, "annex11-11-periodic-evaluation"}, &out); code != 0 {
		t.Fatalf("expected exit 0 when all apps are Synced, got %d:\n%s", code, out.String())
	}
}

func TestDriftRequiresAppFileAndControl(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"drift", "only-one-arg"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}

func TestProvenanceTrustedBuilderAppendsSatisfiedEvidence(t *testing.T) {
	dir := t.TempDir()
	att := filepath.Join(dir, "provenance.json")
	builder := "https://github.com/kasjens/ComplianceFabric/.github/workflows/release.yml@refs/heads/main"
	writeFixture(t, att, `{
	  "_type": "https://in-toto.io/Statement/v1",
	  "subject": [{ "name": "registry.example/mes", "digest": { "sha256": "1f2e" } }],
	  "predicateType": "https://slsa.dev/provenance/v1",
	  "predicate": { "runDetails": { "builder": { "id": "`+builder+`" },
	    "metadata": { "finishedOn": "2026-06-06T10:05:00Z" } } }
	}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	if code := run([]string{"provenance", att, builder, "cfr-part-11-10a-system-validation", "--ledger", led}, &out); code != 0 {
		t.Fatalf("expected exit 0 for trusted-builder provenance, got %d:\n%s", code, out.String())
	}
	var records []struct {
		ControlID string `json:"control-id"`
		Result    string `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("output is not a JSON array of records: %v\n%s", err, out.String())
	}
	if len(records) != 1 || records[0].Result != "satisfied" {
		t.Fatalf("want 1 satisfied record, got %+v", records)
	}
	data, err := os.ReadFile(led)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	if !strings.Contains(string(data), "slsa-provenance") {
		t.Errorf("ledger missing the provenance record:\n%s", string(data))
	}
}

func TestProvenanceUntrustedBuilderExitsOne(t *testing.T) {
	dir := t.TempDir()
	att := filepath.Join(dir, "provenance.json")
	writeFixture(t, att, `{
	  "subject": [{ "name": "registry.example/mes", "digest": { "sha256": "1f2e" } }],
	  "predicateType": "https://slsa.dev/provenance/v1",
	  "predicate": { "runDetails": { "builder": { "id": "https://evil.example/x" } } }
	}`)

	var out bytes.Buffer
	if code := run([]string{"provenance", att, "https://github.com/kasjens/ComplianceFabric/.github/workflows/release.yml@refs/heads/main", "cfr-part-11-10a-system-validation"}, &out); code != 1 {
		t.Fatalf("expected exit 1 for an untrusted builder, got %d:\n%s", code, out.String())
	}
}

func TestProvenanceRequiresThreePositionals(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"provenance", "only", "two"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}

func TestSBOMCleanInventoryAppendsSatisfiedEvidence(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "sbom.json")
	writeFixture(t, sbom, `{
	  "bomFormat": "CycloneDX",
	  "metadata": {
	    "timestamp": "2026-06-06T10:00:00Z",
	    "component": { "name": "registry.example/mes", "version": "1.4.2" }
	  },
	  "components": [ { "name": "openssl", "version": "3.0.8" } ]
	}`)
	policy := filepath.Join(dir, "policy.json")
	writeFixture(t, policy, `{"banned":[{"name":"log4j","version":"2.14.1"}]}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	if code := run([]string{"sbom", sbom, policy, "cfr-part-11-10a-system-validation", "--ledger", led}, &out); code != 0 {
		t.Fatalf("expected exit 0 for a clean inventory, got %d:\n%s", code, out.String())
	}
	var records []struct {
		Result string `json:"result"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("output is not a JSON array of records: %v\n%s", err, out.String())
	}
	if len(records) != 1 || records[0].Result != "satisfied" || records[0].Source != "sbom-content" {
		t.Fatalf("want 1 satisfied sbom-content record, got %+v", records)
	}
	if vcode := run([]string{"ledger", "verify", led}, &bytes.Buffer{}); vcode != 0 {
		t.Errorf("expected ledger to verify, got exit %d", vcode)
	}
}

func TestSBOMBannedComponentExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "sbom.json")
	writeFixture(t, sbom, `{
	  "metadata": { "timestamp": "2026-06-06T10:00:00Z",
	    "component": { "name": "registry.example/mes", "version": "1.4.2" } },
	  "components": [ { "name": "openssl", "version": "3.0.8" } ]
	}`)
	policy := filepath.Join(dir, "policy.json")
	writeFixture(t, policy, `{"banned":[{"name":"openssl","version":"3.0.8"}]}`)

	var out bytes.Buffer
	if code := run([]string{"sbom", sbom, policy, "cfr-part-11-10a-system-validation"}, &out); code != 1 {
		t.Fatalf("expected exit 1 for a banned component, got %d:\n%s", code, out.String())
	}
}

func TestSBOMRequiresThreePositionals(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"sbom", "only", "two"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}

// A release manifest whose generated SBOM is clean clears the gate: the release
// evidence is appended to a fresh ledger that verifies, posture is clean, and the
// command exits 0 so the release pipeline proceeds.
func TestReleaseGateClearsCleanRelease(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "sbom.json")
	writeFixture(t, sbom, `{
	  "metadata": { "timestamp": "2026-06-07T10:00:00Z",
	    "component": { "name": "registry.example/mes", "version": "1.4.2" } },
	  "components": [ { "name": "openssl", "version": "3.0.8" } ]
	}`)
	policy := filepath.Join(dir, "policy.json")
	writeFixture(t, policy, `{"banned":[{"name":"log4j","version":"2.14.1"}]}`)
	manifest := filepath.Join(dir, "release.json")
	writeFixture(t, manifest, `{"release":"mes-1.4.2","sources":[
	  {"type":"sbom","file":"`+sbom+`","control":"cfr-part-11-10a-system-validation","sbom-policy-file":"`+policy+`"}
	]}`)
	led := filepath.Join(dir, "release.ledger")

	var out bytes.Buffer
	if code := run([]string{"release-gate", manifest, "--ledger", led}, &out); code != 0 {
		t.Fatalf("expected exit 0 for a clean release, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "cleared") {
		t.Errorf("expected a cleared message, got:\n%s", out.String())
	}
	if vcode := run([]string{"ledger", "verify", led}, &bytes.Buffer{}); vcode != 0 {
		t.Errorf("expected the release ledger to verify, got exit %d", vcode)
	}
}

// A banned component present in the release blocks the gate: the command exits 1
// so the release pipeline stops.
func TestReleaseGateBlocksOnBannedComponent(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "sbom.json")
	writeFixture(t, sbom, `{
	  "metadata": { "timestamp": "2026-06-07T10:00:00Z",
	    "component": { "name": "registry.example/mes", "version": "1.4.2" } },
	  "components": [ { "name": "openssl", "version": "3.0.8" } ]
	}`)
	policy := filepath.Join(dir, "policy.json")
	writeFixture(t, policy, `{"banned":[{"name":"openssl","version":"3.0.8"}]}`)
	manifest := filepath.Join(dir, "release.json")
	writeFixture(t, manifest, `{"sources":[
	  {"type":"sbom","file":"`+sbom+`","control":"cfr-part-11-10a-system-validation","sbom-policy-file":"`+policy+`"}
	]}`)
	led := filepath.Join(dir, "release.ledger")

	var out bytes.Buffer
	if code := run([]string{"release-gate", manifest, "--ledger", led}, &out); code != 1 {
		t.Fatalf("expected exit 1 for a banned component, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "blocked") {
		t.Errorf("expected a blocked message, got:\n%s", out.String())
	}
}

func TestReleaseGateRequiresManifestArg(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"release-gate"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for a missing manifest arg, got %d", code)
	}
}

// cleanSBOMLedger builds a source ledger holding one satisfied SBOM record keyed
// to the given control, by running the sbom producer against a clean SBOM. It is
// the anchor evidence a crosswalk rolls up to a second-framework citation.
func cleanSBOMLedger(t *testing.T, dir, control string) string {
	t.Helper()
	sbom := filepath.Join(dir, "anchor-sbom.json")
	writeFixture(t, sbom, `{
	  "metadata": { "timestamp": "2026-06-07T10:00:00Z",
	    "component": { "name": "registry.example/mes", "version": "1.4.2" } },
	  "components": [ { "name": "openssl", "version": "3.0.8" } ]
	}`)
	policy := filepath.Join(dir, "anchor-policy.json")
	writeFixture(t, policy, `{"banned":[{"name":"log4j","version":"2.14.1"}]}`)
	led := filepath.Join(dir, "source.ledger")
	if code := run([]string{"sbom", sbom, policy, control, "--ledger", led}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("failed to build the anchor ledger, sbom producer exit %d", code)
	}
	return led
}

// A satisfied anchor control rolls up under the target-sector citation: the same
// enforced control answers a second framework with no new enforcement.
func TestCrosswalkRollsAnchorEvidenceToTargetCitation(t *testing.T) {
	dir := t.TempDir()
	src := cleanSBOMLedger(t, dir, "cfr-part-11-10a-system-validation")
	cw := filepath.Join(dir, "crosswalk.json")
	writeFixture(t, cw, `{"mappings":[
	  {"control":"dora-9-2-ict-supply-chain","satisfied-by":["cfr-part-11-10a-system-validation"]}
	]}`)

	var out bytes.Buffer
	if code := run([]string{"crosswalk", cw, src}, &out); code != 0 {
		t.Fatalf("expected exit 0 for a satisfied crosswalk, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "dora-9-2-ict-supply-chain") {
		t.Errorf("expected a derived DORA record, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "satisfied") {
		t.Errorf("expected the derived record to be satisfied, got:\n%s", out.String())
	}
}

// A crosswalk to a control with no anchor evidence is not satisfied, and the
// command exits 1 so a gap in the second framework surfaces.
func TestCrosswalkUnmappedAnchorIsNotSatisfied(t *testing.T) {
	dir := t.TempDir()
	src := cleanSBOMLedger(t, dir, "cfr-part-11-10a-system-validation")
	cw := filepath.Join(dir, "crosswalk.json")
	writeFixture(t, cw, `{"mappings":[
	  {"control":"nis2-21-2-d-supply-chain","satisfied-by":["control-with-no-evidence"]}
	]}`)

	var out bytes.Buffer
	if code := run([]string{"crosswalk", cw, src}, &out); code != 1 {
		t.Fatalf("expected exit 1 for an unsatisfied crosswalk, got %d:\n%s", code, out.String())
	}
}

// The derived records can be appended to a ledger that then verifies, so the
// second-framework rollup becomes durable evidence like any other.
func TestCrosswalkAppendsDerivedRecordsToLedger(t *testing.T) {
	dir := t.TempDir()
	src := cleanSBOMLedger(t, dir, "cfr-part-11-10a-system-validation")
	cw := filepath.Join(dir, "crosswalk.json")
	writeFixture(t, cw, `{"mappings":[
	  {"control":"dora-9-2-ict-supply-chain","satisfied-by":["cfr-part-11-10a-system-validation"]}
	]}`)
	out := filepath.Join(dir, "crosswalk.ledger")

	if code := run([]string{"crosswalk", cw, src, "--ledger", out}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if vcode := run([]string{"ledger", "verify", out}, &bytes.Buffer{}); vcode != 0 {
		t.Errorf("expected the crosswalk ledger to verify, got exit %d", vcode)
	}
}

func TestCrosswalkRequiresTwoArgs(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"crosswalk", "only-one"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for a missing argument, got %d", code)
	}
}

// The shipped NIS2 crosswalk answers its supply-chain citation from the same
// Part 11 system-validation control the DORA crosswalk uses: a satisfied
// supply-chain anchor rolls up under NIS2 Article 21(2)(d) with no new
// enforcement. Running it against the real artifact proves the committed file is
// valid and wired to anchors that exist.
func TestCrosswalkRollsShippedNIS2SupplyChain(t *testing.T) {
	dir := t.TempDir()
	src := cleanSBOMLedger(t, dir, "cfr-part-11-10a-system-validation")

	var out bytes.Buffer
	code := run([]string{"crosswalk", "../../controls/crosswalks/nis2.json", src}, &out)
	// Some NIS2 citations map to anchors not present in this minimal ledger, so a
	// non-zero exit (open gaps) is expected; the supply-chain citation must be
	// satisfied and present in the output.
	if code != 1 {
		t.Fatalf("expected exit 1 (some citations unsatisfied) for the shipped NIS2 crosswalk, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "nis2-21-2-d-supply-chain-security") {
		t.Fatalf("expected the NIS2 supply-chain citation in the output, got:\n%s", out.String())
	}
	// The supply-chain citation, whose anchor is satisfied, must be satisfied.
	var recs []evidence.Record
	if err := json.Unmarshal(out.Bytes(), &recs); err != nil {
		t.Fatalf("crosswalk output is not record JSON: %v\n%s", err, out.String())
	}
	found := false
	for _, r := range recs {
		if r.ControlID == "nis2-21-2-d-supply-chain-security" {
			found = true
			if r.Result != "satisfied" {
				t.Errorf("NIS2 supply-chain citation = %q, want satisfied", r.Result)
			}
		}
	}
	if !found {
		t.Error("NIS2 supply-chain citation missing from derived records")
	}
}

// driftAppsFixture writes an Argo applications JSON file with the given sync
// status and returns its path, for use as a collect source's fetch input.
func driftAppsFixture(t *testing.T, dir, status string) string {
	t.Helper()
	p := filepath.Join(dir, "apps-"+status+".json")
	writeFixture(t, p, `{"items":[{"metadata":{"name":"web"},"status":{"sync":{"status":"`+status+
		`"},"reconciledAt":"2026-01-01T00:00:00Z"}}]}`)
	return p
}

// A single --once tick fetches each configured source via its command, produces
// evidence, and appends the changes to the ledger, which then verifies.
func TestCollectOnceAppendsChangesAndVerifies(t *testing.T) {
	dir := t.TempDir()
	apps := driftAppsFixture(t, dir, "Synced")
	cfgPath := filepath.Join(dir, "collect.json")
	writeFixture(t, cfgPath, `{"interval":"30s","sources":[
	  {"type":"drift","command":["cat","`+apps+`"],"control":"annex11-11-periodic-evaluation"}
	]}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	if code := run([]string{"collect", cfgPath, "--ledger", led, "--once"}, &out); code != 0 {
		t.Fatalf("expected exit 0 for a clean one-shot tick, got %d:\n%s", code, out.String())
	}
	data, err := os.ReadFile(led)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	if !strings.Contains(string(data), "annex11-11-periodic-evaluation") {
		t.Errorf("ledger missing the collected control:\n%s", string(data))
	}
	if vcode := run([]string{"ledger", "verify", led}, &bytes.Buffer{}); vcode != 0 {
		t.Errorf("expected the collected ledger to verify, got exit %d", vcode)
	}
}

// An unchanged second --once tick appends nothing: the ledger keeps exactly the
// one baseline entry (event-log semantics through the CLI).
func TestCollectOnceIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	apps := driftAppsFixture(t, dir, "Synced")
	cfgPath := filepath.Join(dir, "collect.json")
	writeFixture(t, cfgPath, `{"interval":"30s","sources":[
	  {"type":"drift","command":["cat","`+apps+`"],"control":"c1"}
	]}`)
	led := filepath.Join(dir, "ledger.jsonl")

	if code := run([]string{"collect", cfgPath, "--ledger", led, "--once"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("first tick: expected exit 0, got %d", code)
	}
	if code := run([]string{"collect", cfgPath, "--ledger", led, "--once"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("second tick: expected exit 0, got %d", code)
	}
	data, err := os.ReadFile(led)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	if lines := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; lines != 1 {
		t.Fatalf("expected exactly 1 ledger entry after two unchanged ticks, got %d:\n%s", lines, string(data))
	}
}

// A source whose fetch command cannot run does not abort the tick, but the tick
// reports the failure as a non-zero exit so a broken source is visible.
func TestCollectReportsSourceFailure(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "collect.json")
	writeFixture(t, cfgPath, `{"interval":"30s","sources":[
	  {"type":"drift","command":["this-command-does-not-exist-xyz"],"control":"c1"}
	]}`)
	led := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	if code := run([]string{"collect", cfgPath, "--ledger", led, "--once"}, &out); code != 1 {
		t.Fatalf("expected exit 1 when a source fails to fetch, got %d:\n%s", code, out.String())
	}
}

func TestCollectRequiresConfigArg(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"collect", "--ledger", "x.jsonl", "--once"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for a missing config arg, got %d", code)
	}
}

func TestCollectRequiresLedger(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "collect.json")
	writeFixture(t, cfgPath, `{"interval":"30s","sources":[]}`)
	var out bytes.Buffer
	if code := run([]string{"collect", cfgPath, "--once"}, &out); code != 2 {
		t.Fatalf("expected exit 2 when --ledger is absent, got %d", code)
	}
}

func TestCollectBadConfigExitsTwo(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "collect.json")
	writeFixture(t, cfgPath, `{"interval":"30s","sources":[{"type":"nope","command":["x"]}]}`)
	led := filepath.Join(dir, "ledger.jsonl")
	var out bytes.Buffer
	if code := run([]string{"collect", cfgPath, "--ledger", led, "--once"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for an unloadable config, got %d:\n%s", code, out.String())
	}
}

func TestServeRequiresLedgerArg(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"serve"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for a missing ledger arg, got %d", code)
	}
}

func TestServeDanglingAddrIsUsageError(t *testing.T) {
	var out bytes.Buffer
	// --addr with no following value is a usage error caught before any listener
	// binds, so the wiring is exercised without occupying a port.
	if code := run([]string{"serve", "led.jsonl", "--addr"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for a dangling --addr, got %d", code)
	}
}

func TestServeUnreadableLedgerExitsTwo(t *testing.T) {
	var out bytes.Buffer
	// A ledger path that is a directory cannot be read as a ledger; this is caught
	// up front (before any listener binds) so the test never occupies a port.
	if code := run([]string{"serve", t.TempDir(), "--addr", ":0"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for an unreadable ledger, got %d:\n%s", code, out.String())
	}
}

func TestUsageOnBadArgs(t *testing.T) {
	var out bytes.Buffer
	if code := run(nil, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}

func TestRegistryValidateCleanExitsZero(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "agents", "a.json"),
		`{"id":"a","version":"1.0.0","owner":"o","prompts":["p"],"tools":["t"]}`)
	writeFixture(t, filepath.Join(dir, "prompts", "p.json"),
		`{"id":"p","version":"1.0.0","text":"hi"}`)
	writeFixture(t, filepath.Join(dir, "tools", "t.json"),
		`{"id":"t","version":"1.0.0","description":"a tool"}`)

	var out bytes.Buffer
	if code := run([]string{"registry", "validate", dir}, &out); code != 0 {
		t.Fatalf("expected exit 0 for clean registry, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "no findings") {
		t.Errorf("expected clean-result message, got:\n%s", out.String())
	}
}

func TestRegistryValidateReportsFindingsAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "agents", "a.json"),
		`{"id":"a","prompts":["ghost"]}`)

	var out bytes.Buffer
	code := run([]string{"registry", "validate", dir}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 for findings, got %d:\n%s", code, out.String())
	}
	for _, want := range []string{"missing-version", "missing-owner", "unknown-prompt-ref"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("expected %q in output, got:\n%s", want, out.String())
		}
	}
}

func seedTraceRegistry(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "agents", "a.json"),
		`{"id":"release-reviewer","version":"1.0.0","owner":"o","prompts":["review"],"tools":["gh-pr-read"]}`)
	writeFixture(t, filepath.Join(dir, "prompts", "p.json"),
		`{"id":"review","version":"1.0.0","text":"hi"}`)
	writeFixture(t, filepath.Join(dir, "tools", "t.json"),
		`{"id":"gh-pr-read","version":"1.0.0","description":"reads prs"}`)
	return dir
}

func TestTraceConformingInteractionExitsZeroAndAppendsToLedger(t *testing.T) {
	dir := t.TempDir()
	tracesFile := filepath.Join(dir, "traces.json")
	writeFixture(t, tracesFile,
		`{"traces":[{"id":"t1","agent":"release-reviewer","prompt":"review","tools":["gh-pr-read"],"timestamp":"2026-06-06T09:14:00Z"}]}`)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	code := run([]string{"trace", tracesFile, seedTraceRegistry(t), "eu-ai-act-12-record-keeping", "--ledger", ledgerPath}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for conforming interaction, got %d:\n%s", code, out.String())
	}
	if _, err := os.Stat(ledgerPath); err != nil {
		t.Errorf("expected ledger written: %v", err)
	}
	if vcode := run([]string{"ledger", "verify", ledgerPath}, &bytes.Buffer{}); vcode != 0 {
		t.Errorf("expected ledger to verify, got exit %d", vcode)
	}
}

func TestTraceOffPolicyInteractionExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	tracesFile := filepath.Join(dir, "traces.json")
	writeFixture(t, tracesFile,
		`{"traces":[{"id":"t1","agent":"release-reviewer","prompt":"review","tools":["rm-rf"],"timestamp":"2026-06-06T09:14:00Z"}]}`)

	var out bytes.Buffer
	code := run([]string{"trace", tracesFile, seedTraceRegistry(t), "eu-ai-act-12-record-keeping"}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 for off-policy interaction, got %d:\n%s", code, out.String())
	}
}

func TestTraceRequiresThreePositionalArgs(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"trace", "only", "two"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}

func TestGatewayRequiresRegistryArg(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"gateway"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing registry arg, got %d", code)
	}
}

func TestGatewayUnknownFlagValueIsUsageError(t *testing.T) {
	var out bytes.Buffer
	// --addr with no following value is a usage error caught before any listener
	// is bound, so the wiring is exercised without occupying a port.
	if code := run([]string{"gateway", "reg", "--addr"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for dangling --addr, got %d", code)
	}
}

func TestGatewayUncompilableGuardrailExitsTwo(t *testing.T) {
	dir := t.TempDir()
	// A clean registry so loading succeeds and the failure is unambiguously the
	// guardrail policy, not the registry.
	writeFixture(t, filepath.Join(dir, "agents", "a.json"),
		`{"id":"a","version":"1.0.0","owner":"o","prompts":["p"],"tools":["t"]}`)
	writeFixture(t, filepath.Join(dir, "prompts", "p.json"), `{"id":"p","version":"1.0.0","text":"hi"}`)
	writeFixture(t, filepath.Join(dir, "tools", "t.json"), `{"id":"t","version":"1.0.0","description":"a tool"}`)
	guardrail := filepath.Join(dir, "guardrail.json")
	writeFixture(t, guardrail, `{"rules":[{"name":"broken","pattern":"("}]}`)

	var out bytes.Buffer
	// An uncompilable guardrail is rejected before the listener binds, so this
	// never occupies a port.
	if code := run([]string{"gateway", dir, "--guardrail", guardrail, "--addr", ":0"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for an uncompilable guardrail, got %d:\n%s", code, out.String())
	}
}

func TestGatewayUnparseableLimitsExitsTwo(t *testing.T) {
	dir := t.TempDir()
	// A clean registry so loading succeeds and the failure is unambiguously the
	// limits file, not the registry.
	writeFixture(t, filepath.Join(dir, "agents", "a.json"),
		`{"id":"a","version":"1.0.0","owner":"o","prompts":["p"],"tools":["t"]}`)
	writeFixture(t, filepath.Join(dir, "prompts", "p.json"), `{"id":"p","version":"1.0.0","text":"hi"}`)
	writeFixture(t, filepath.Join(dir, "tools", "t.json"), `{"id":"t","version":"1.0.0","description":"a tool"}`)
	limits := filepath.Join(dir, "limits.json")
	// An unparseable window duration is rejected before the listener binds, so a
	// budget the gateway could not fully apply never silently goes unenforced.
	writeFixture(t, limits, `{"a":{"max-requests":1,"window":"1 fortnight"}}`)

	var out bytes.Buffer
	if code := run([]string{"gateway", dir, "--limits", limits, "--addr", ":0"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for an unparseable limits file, got %d:\n%s", code, out.String())
	}
}

func TestGatewayProxyRequiresUpstream(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "agents", "a.json"),
		`{"id":"a","version":"1.0.0","owner":"o","prompts":["p"],"tools":["t"]}`)
	writeFixture(t, filepath.Join(dir, "prompts", "p.json"), `{"id":"p","version":"1.0.0","text":"hi"}`)
	writeFixture(t, filepath.Join(dir, "tools", "t.json"), `{"id":"t","version":"1.0.0","description":"a tool"}`)

	var out bytes.Buffer
	// Without --upstream the proxy has nowhere to forward, so it is a usage error
	// caught before any listener binds.
	if code := run([]string{"gateway-proxy", dir, "--addr", ":0"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for gateway-proxy with no --upstream, got %d:\n%s", code, out.String())
	}
}

func TestGatewayProxyRejectsInvalidUpstream(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "agents", "a.json"),
		`{"id":"a","version":"1.0.0","owner":"o","prompts":["p"],"tools":["t"]}`)
	writeFixture(t, filepath.Join(dir, "prompts", "p.json"), `{"id":"p","version":"1.0.0","text":"hi"}`)
	writeFixture(t, filepath.Join(dir, "tools", "t.json"), `{"id":"t","version":"1.0.0","description":"a tool"}`)

	var out bytes.Buffer
	// A URL with no scheme/host is rejected before the listener binds, so the
	// proxy never starts forwarding to a destination it cannot reach.
	if code := run([]string{"gateway-proxy", dir, "--upstream", "not-a-url", "--addr", ":0"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for an invalid --upstream, got %d:\n%s", code, out.String())
	}
}

func TestGatewayProxyUnparseableLimitsExitsTwo(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "agents", "a.json"),
		`{"id":"a","version":"1.0.0","owner":"o","prompts":["p"],"tools":["t"]}`)
	writeFixture(t, filepath.Join(dir, "prompts", "p.json"), `{"id":"p","version":"1.0.0","text":"hi"}`)
	writeFixture(t, filepath.Join(dir, "tools", "t.json"), `{"id":"t","version":"1.0.0","description":"a tool"}`)
	limits := filepath.Join(dir, "limits.json")
	writeFixture(t, limits, `{"a":{"max-requests":1,"window":"1 fortnight"}}`)

	var out bytes.Buffer
	// The shared gate-loading rejects a bad limits file for the proxy too, before
	// the listener binds.
	if code := run([]string{"gateway-proxy", dir, "--upstream", "http://localhost:1234", "--limits", limits, "--addr", ":0"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for an unparseable limits file, got %d:\n%s", code, out.String())
	}
}

func TestEvalGatePromotedVersionExitsZeroAndAppendsToLedger(t *testing.T) {
	dir := t.TempDir()
	runFile := filepath.Join(dir, "run.json")
	writeFixture(t, runFile, `{"agent":"a","version":"1.0.0","run-at":"2026-06-06T10:00:00Z",
		"results":[{"case":"inj-1","suite":"prompt-injection","passed":true}]}`)
	gateFile := filepath.Join(dir, "gate.json")
	writeFixture(t, gateFile, `{"required-suites":["prompt-injection"],"max-failures":0}`)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	var out bytes.Buffer
	code := run([]string{"eval-gate", runFile, gateFile, "eu-ai-act-15-accuracy-robustness", "--ledger", ledgerPath}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for promoted version, got %d:\n%s", code, out.String())
	}
	if vcode := run([]string{"ledger", "verify", ledgerPath}, &bytes.Buffer{}); vcode != 0 {
		t.Errorf("expected ledger to verify, got exit %d", vcode)
	}
}

func TestEvalGateBlockedVersionExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	runFile := filepath.Join(dir, "run.json")
	writeFixture(t, runFile, `{"agent":"a","version":"1.1.0","run-at":"2026-06-06T10:00:00Z",
		"results":[{"case":"inj-1","suite":"prompt-injection","passed":false}]}`)
	gateFile := filepath.Join(dir, "gate.json")
	writeFixture(t, gateFile, `{"required-suites":["prompt-injection"],"max-failures":0}`)

	var out bytes.Buffer
	code := run([]string{"eval-gate", runFile, gateFile, "eu-ai-act-15-accuracy-robustness"}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 for blocked version, got %d:\n%s", code, out.String())
	}
}

func TestEvalGateRequiresThreePositionalArgs(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"eval-gate", "run.json", "gate.json"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}

// evalGateLedger builds a source ledger holding one satisfied eval-gate record
// keyed to the given control, by promoting an all-passing evaluation run through
// a gate. It is the agent-layer anchor evidence an ISO 42001 / EU AI Act
// crosswalk rolls up.
func evalGateLedger(t *testing.T, dir, control string) string {
	t.Helper()
	runFile := filepath.Join(dir, "eval-run.json")
	writeFixture(t, runFile, `{"agent":"release-reviewer","version":"1.0.0","run-at":"2026-06-07T10:00:00Z",
		"results":[{"case":"inj-1","suite":"prompt-injection","passed":true}]}`)
	gateFile := filepath.Join(dir, "eval-gate.json")
	writeFixture(t, gateFile, `{"required-suites":["prompt-injection"],"max-failures":0}`)
	led := filepath.Join(dir, "agent.ledger")
	if code := run([]string{"eval-gate", runFile, gateFile, control, "--ledger", led}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("failed to build the agent-layer anchor ledger, eval-gate exit %d", code)
	}
	return led
}

// The shipped ISO 42001 crosswalk answers its verification/validation citation
// from the same EU AI Act eval-gate control the agent layer already evidences:
// a satisfied pre-promotion eval gate rolls up under ISO 42001 with no new
// enforcement. Running it against the real artifact proves the committed file is
// valid and wired to anchors that exist.
func TestCrosswalkRollsShippedISO42001(t *testing.T) {
	dir := t.TempDir()
	src := evalGateLedger(t, dir, "eu-ai-act-15-accuracy-robustness")

	var out bytes.Buffer
	// The record-keeping citation maps to an anchor not present in this minimal
	// ledger, so a non-zero exit (open gaps) is expected; the verification one
	// must be satisfied.
	code := run([]string{"crosswalk", "../../controls/crosswalks/iso-42001.json", src}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 (some citations unsatisfied) for the shipped ISO 42001 crosswalk, got %d:\n%s", code, out.String())
	}
	var recs []evidence.Record
	if err := json.Unmarshal(out.Bytes(), &recs); err != nil {
		t.Fatalf("crosswalk output is not record JSON: %v\n%s", err, out.String())
	}
	found := false
	for _, r := range recs {
		if r.ControlID == "iso-42001-a-6-2-4-verification-validation" {
			found = true
			if r.Result != "satisfied" {
				t.Errorf("ISO 42001 verification/validation citation = %q, want satisfied", r.Result)
			}
		}
	}
	if !found {
		t.Error("ISO 42001 verification/validation citation missing from derived records")
	}
}

func TestRegistryRequiresSubcommandAndPath(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"registry", "validate"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing path, got %d", code)
	}
	if code := run([]string{"registry", "bogus", "somedir"}, &out); code != 2 {
		t.Fatalf("expected exit 2 for unknown subcommand, got %d", code)
	}
}
