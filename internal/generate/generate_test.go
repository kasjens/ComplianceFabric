package generate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

// kyvernoComponent builds a component whose rule sets map the given controls to
// Kyverno checks. checks is control-id -> []check-id.
func kyvernoComponent(checks map[string][]string) oscal.Component {
	comp := oscal.Component{Title: "kyverno", Type: "validation"}
	seen := map[string]bool{}
	i := 0
	ruleFor := map[string]string{}
	for _, checkIDs := range checks {
		for _, check := range checkIDs {
			if seen[check] {
				continue
			}
			seen[check] = true
			group := "rule_set_" + string(rune('0'+i))
			rule := "rule-" + check
			ruleFor[check] = rule
			comp.Props = append(comp.Props,
				oscal.Prop{Name: "Rule_Id", Value: rule, Remarks: group},
				oscal.Prop{Name: "Check_Id", Value: check, Remarks: group},
			)
			i++
		}
	}
	ci := oscal.ControlImplementation{Source: "profile"}
	for control, checkIDs := range checks {
		req := oscal.ImplementedRequirement{ControlID: control}
		for _, check := range checkIDs {
			req.Props = append(req.Props, oscal.Prop{Name: "Rule_Id", Value: ruleFor[check]})
		}
		ci.ImplementedRequirements = append(ci.ImplementedRequirements, req)
	}
	comp.ControlImplementations = []oscal.ControlImplementation{ci}
	return comp
}

func bundle(selected []string, checks map[string][]string) validate.Bundle {
	return validate.Bundle{
		Profiles: []oscal.Profile{{Imports: []oscal.Import{{Href: "cat", IncludeControls: selected}}}},
		ComponentDefinitions: []oscal.ComponentDefinition{{
			Components: []oscal.Component{kyvernoComponent(checks)},
		}},
	}
}

func writePolicyFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	kdir := filepath.Join(dir, "kyverno")
	if err := os.MkdirAll(kdir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		body := "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: " + n + "\n"
		if err := os.WriteFile(filepath.Join(kdir, n+".yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func checkIDs(r Result) []string {
	var ids []string
	for _, p := range r.Policies {
		ids = append(ids, p.CheckID)
	}
	return ids
}

func TestComposeSelectsOnlyPoliciesForSelectedControls(t *testing.T) {
	dir := t.TempDir()
	writePolicyFiles(t, dir, "policy-a", "policy-b", "policy-unselected")
	b := bundle([]string{"c1"}, map[string][]string{
		"c1": {"policy-a", "policy-b"},
		"c2": {"policy-unselected"},
	})

	r, err := Compose(b, dir)
	if err != nil {
		t.Fatalf("Compose returned error: %v", err)
	}
	got := checkIDs(r)
	if len(got) != 2 {
		t.Fatalf("expected 2 composed policies, got %v", got)
	}
	for _, id := range got {
		if id == "policy-unselected" {
			t.Errorf("policy for unselected control c2 was composed: %v", got)
		}
	}
}

func TestComposeDeduplicatesSharedPolicy(t *testing.T) {
	dir := t.TempDir()
	writePolicyFiles(t, dir, "shared")
	b := bundle([]string{"c1", "c2"}, map[string][]string{
		"c1": {"shared"},
		"c2": {"shared"},
	})

	r, err := Compose(b, dir)
	if err != nil {
		t.Fatalf("Compose returned error: %v", err)
	}
	if got := checkIDs(r); len(got) != 1 || got[0] != "shared" {
		t.Fatalf("expected one deduped policy [shared], got %v", got)
	}
}

func TestComposeErrorsWhenPolicyFileMissing(t *testing.T) {
	dir := t.TempDir() // no files written
	b := bundle([]string{"c1"}, map[string][]string{"c1": {"absent"}})

	if _, err := Compose(b, dir); err == nil {
		t.Fatal("expected an error when a referenced policy file is missing")
	}
}

func TestWriteEmitsComposedPolicies(t *testing.T) {
	src := t.TempDir()
	writePolicyFiles(t, src, "policy-a")
	b := bundle([]string{"c1"}, map[string][]string{"c1": {"policy-a"}})
	r, err := Compose(b, src)
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	if err := Write(r, out); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	written := filepath.Join(out, "kyverno", "policy-a.yaml")
	if _, err := os.Stat(written); err != nil {
		t.Fatalf("expected composed policy at %s: %v", written, err)
	}
}
