package policies

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

func TestExtractControlIDs(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"single unquoted", "metadata:\n  annotations:\n    fabric.control-id: c-1\n", []string{"c-1"}},
		{"quoted list", "  annotations:\n    fabric.control-id: \"a, b\"\n", []string{"a", "b"}},
		{"absent", "metadata:\n  name: x\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractControlIDs([]byte(tc.yaml))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("got[%d]=%q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func writePolicy(t *testing.T, dir, policyID, controlIDAnnotation string) {
	t.Helper()
	kdir := filepath.Join(dir, "kyverno")
	if err := os.MkdirAll(kdir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: " + policyID +
		"\n  annotations:\n    fabric.control-id: \"" + controlIDAnnotation + "\"\n"
	if err := os.WriteFile(filepath.Join(kdir, policyID+".yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func bundleMapping(controlID, policyID, component string) validate.Bundle {
	return validate.Bundle{
		ComponentDefinitions: []oscal.ComponentDefinition{{
			Components: []oscal.Component{{
				Title: component,
				Props: []oscal.Prop{
					{Name: "Rule_Id", Value: "r", Remarks: "rule_set_00"},
					{Name: "Check_Id", Value: policyID, Remarks: "rule_set_00"},
				},
				ControlImplementations: []oscal.ControlImplementation{{
					ImplementedRequirements: []oscal.ImplementedRequirement{{
						ControlID: controlID,
						Props:     []oscal.Prop{{Name: "Rule_Id", Value: "r"}},
					}},
				}},
			}},
		}},
	}
}

func rules(fs []validate.Finding, rule string) []validate.Finding {
	var out []validate.Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestVerifyPassesWhenPolicyExistsAndAnnotationMatches(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p1", "c1")
	if fs := Verify(bundleMapping("c1", "p1", "kyverno"), dir); len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestVerifyFlagsMissingPolicyFile(t *testing.T) {
	dir := t.TempDir()
	fs := rules(Verify(bundleMapping("c1", "p1", "kyverno"), dir), "missing-policy")
	if len(fs) != 1 {
		t.Fatalf("expected 1 missing-policy finding, got %+v", fs)
	}
}

func TestVerifyFlagsAnnotationMismatch(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p1", "some-other-control")
	fs := rules(Verify(bundleMapping("c1", "p1", "kyverno"), dir), "policy-control-id-mismatch")
	if len(fs) != 1 {
		t.Fatalf("expected 1 mismatch finding, got %+v", fs)
	}
}

func TestVerifyIgnoresNonKyvernoComponents(t *testing.T) {
	dir := t.TempDir()
	if fs := Verify(bundleMapping("c1", "append-only-storage", "evidence-ledger"), dir); len(fs) != 0 {
		t.Fatalf("non-kyverno components should not require a Kyverno policy file, got %+v", fs)
	}
}
