package policies

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression tests. Each of these failed before the fix that accompanies it.

// A YAML file may hold several documents separated by "---", each its own policy
// with its own fabric.control-id annotation. Returning at the first annotation
// silently dropped every later document's control mapping, which is
// indistinguishable from that policy simply not being mapped.
func TestExtractControlIDsReadsEveryDocument(t *testing.T) {
	doc := []byte(`apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
  annotations:
    fabric.control-id: cfr-part-11-10a-system-validation
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-audit-annotations
  annotations:
    fabric.control-id: "annex11-9-audit-trail,cfr-part-11-10e-audit-trail"
`)

	got := ExtractControlIDs(doc)

	want := []string{
		"cfr-part-11-10a-system-validation",
		"annex11-9-audit-trail",
		"cfr-part-11-10e-audit-trail",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d control ids %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("control id %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// filepath.Glob treats the directory part of its pattern as a pattern too, so an
// ordinary path containing a glob metacharacter matched nothing and returned
// (nil, nil) — a green traceability check that verified no policies at all. A
// Jenkins workspace directory ("workspace[1]") is the usual way to meet this.
func TestControlsByPolicyHandlesGlobMetacharactersInPath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace[1]")
	kyverno := filepath.Join(root, "kyverno")
	if err := os.MkdirAll(kyverno, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := []byte(`apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
  annotations:
    fabric.control-id: cfr-part-11-10a-system-validation
`)
	if err := os.WriteFile(filepath.Join(kyverno, "require-signed-images.yaml"), policy, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ControlsByPolicy(root)
	if err != nil {
		t.Fatalf("ControlsByPolicy: %v", err)
	}
	ids, ok := got["require-signed-images"]
	if !ok {
		t.Fatalf("policy in a bracketed path was not found at all (got %v); "+
			"traceability would report clean having checked nothing", got)
	}
	if len(ids) != 1 || ids[0] != "cfr-part-11-10a-system-validation" {
		t.Errorf("got control ids %v, want [cfr-part-11-10a-system-validation]", ids)
	}
}

// A missing kyverno directory is an empty result, not an error.
func TestControlsByPolicyMissingDirIsEmpty(t *testing.T) {
	got, err := ControlsByPolicy(t.TempDir())
	if err != nil {
		t.Fatalf("ControlsByPolicy: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}
