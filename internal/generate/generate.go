// Package generate composes the deployable Kyverno policy set for the controls a
// profile selects. It is a deliberately small, native stand-in for the
// composition step Compliance-to-Policy performs: it selects and assembles
// existing policy resources by rule, rather than authoring policy bodies. When
// C2P is wired in, this composer is replaced, not the control source.
package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kasjens/ComplianceFabric/internal/validate"
)

// validateCheckID rejects a check id that is not a plain file stem. Check_Id is
// a raw prop value from GitOps-authored component-definition JSON, and it is used
// to build both a read path in the policy library and a write path in the output
// directory. filepath.Join CLEANS "../" rather than rejecting it, so an
// unvalidated value escapes both directories - letting authored control content
// read arbitrary files and write them back out with mode 0644.
func validateCheckID(check string) error {
	if check == "" {
		return fmt.Errorf("check id is empty")
	}
	if check != filepath.Base(check) {
		return fmt.Errorf("check id %q must be a plain file name", check)
	}
	if check == "." || check == ".." {
		return fmt.Errorf("check id %q is not a valid file name", check)
	}
	if filepath.IsAbs(check) || strings.ContainsAny(check, `/\`) {
		return fmt.Errorf("check id %q must not contain a path", check)
	}
	if strings.Contains(check, "..") {
		return fmt.Errorf("check id %q must not contain %q", check, "..")
	}
	return nil
}

// Policy is one composed Kyverno policy: its check (file stem) and the resource
// body read from the policy library.
type Policy struct {
	CheckID string
	Body    []byte
}

// Result is the composed policy set for a bundle's selected controls.
type Result struct {
	SelectedControls []string
	Policies         []Policy
}

// Compose resolves the controls selected by the bundle's profiles down to the
// unique set of Kyverno policies that enforce them, reading each policy body
// from policiesDir/kyverno/<check>.yaml. It errors if a referenced policy file
// is missing, since an incomplete set cannot be safely deployed.
func Compose(b validate.Bundle, policiesDir string) (Result, error) {
	selected, order := selectedControls(b)

	checksByControl := map[string][]string{}
	for _, cd := range b.ComponentDefinitions {
		for _, cp := range cd.ControlPolicies() {
			if cp.Component != "kyverno" || cp.PolicyID == "" {
				continue
			}
			checksByControl[cp.ControlID] = append(checksByControl[cp.ControlID], cp.PolicyID)
		}
	}

	res := Result{SelectedControls: order}
	seen := map[string]bool{}
	var missing []string
	for _, control := range order {
		if !selected[control] {
			continue
		}
		for _, check := range checksByControl[control] {
			if seen[check] {
				continue
			}
			seen[check] = true
			if err := validateCheckID(check); err != nil {
				return Result{}, fmt.Errorf("control %s: %w", control, err)
			}
			path := filepath.Join(policiesDir, "kyverno", check+".yaml")
			body, err := os.ReadFile(path)
			if err != nil {
				missing = append(missing, path)
				continue
			}
			res.Policies = append(res.Policies, Policy{CheckID: check, Body: body})
		}
	}
	if len(missing) > 0 {
		return Result{}, fmt.Errorf("cannot compose policy set, missing policy files: %s", strings.Join(missing, ", "))
	}
	return res, nil
}

// Write emits each composed policy to outDir/kyverno/<check>.yaml.
func Write(r Result, outDir string) error {
	kdir := filepath.Join(outDir, "kyverno")
	if err := os.MkdirAll(kdir, 0o755); err != nil {
		return err
	}
	for _, p := range r.Policies {
		// Revalidated here rather than trusted from Compose: Write is exported and
		// a Result can be built by any caller.
		if err := validateCheckID(p.CheckID); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(kdir, p.CheckID+".yaml"), p.Body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// selectedControls returns the set of controls the bundle's profiles select,
// plus their first-seen order for deterministic output.
func selectedControls(b validate.Bundle) (map[string]bool, []string) {
	selected := map[string]bool{}
	var order []string
	for _, prof := range b.Profiles {
		for _, imp := range prof.Imports {
			for _, id := range imp.IncludeControls {
				if !selected[id] {
					selected[id] = true
					order = append(order, id)
				}
			}
		}
	}
	return selected, order
}
