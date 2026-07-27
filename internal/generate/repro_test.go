package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REPRODUCTION — Workstream R.2, plan item 5.1. Expected to FAIL against cac9f78.

// Write joins the raw Check_Id into the output path. Check_Id is an unvalidated
// prop value from GitOps-authored component-definition JSON, and filepath.Join
// CLEANS "../" rather than rejecting it, so a crafted check id escapes the output
// directory and writes an arbitrary file with mode 0644 — for example over
// ~/.ssh/authorized_keys on a CI runner.
func TestRepro51WriteMustRejectTraversingCheckID(t *testing.T) {
	root := t.TempDir()
	outDir := filepath.Join(root, "out")
	// A sentinel the traversal would land in, one level above outDir.
	outside := filepath.Join(root, "pwned.yaml")

	cases := []string{
		"../pwned",
		"../../pwned",
		filepath.Join("..", "..", "pwned"),
	}

	for _, check := range cases {
		t.Run(check, func(t *testing.T) {
			os.Remove(outside)

			r := Result{Policies: []Policy{{CheckID: check, Body: []byte("owned: true\n")}}}
			err := Write(r, outDir)
			if err == nil {
				t.Errorf("Write accepted traversing check id %q; it must be rejected", check)
			}

			// The decisive assertion: nothing may be created outside outDir.
			if matches, _ := filepath.Glob(filepath.Join(root, "*.yaml")); len(matches) > 0 {
				t.Errorf("check id %q wrote outside the output directory: %v", check, matches)
			}
		})
	}
}

// Benign check ids must keep working — this guards the fix against overreach.
func TestRepro51BenignCheckIDStillWrites(t *testing.T) {
	outDir := t.TempDir()
	r := Result{Policies: []Policy{{CheckID: "require-signed-images", Body: []byte("ok: true\n")}}}

	if err := Write(r, outDir); err != nil {
		t.Fatalf("Write rejected a benign check id: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "kyverno", "require-signed-images.yaml"))
	if err != nil {
		t.Fatalf("expected policy file: %v", err)
	}
	if !strings.Contains(string(got), "ok: true") {
		t.Errorf("unexpected body %q", got)
	}
}
