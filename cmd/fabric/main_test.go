package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

func TestUsageOnBadArgs(t *testing.T) {
	var out bytes.Buffer
	if code := run(nil, &out); code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}
