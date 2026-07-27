package policies

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kasjens/ComplianceFabric/internal/validate"
)

const annotationKey = "fabric.control-id:"

// ExtractControlIDs scans a Kyverno policy document for the fabric.control-id
// annotation and returns the control IDs it declares. The value may be a single
// ID or a quoted, comma-separated list. Returns nil when the annotation is absent.
//
// A YAML file may hold several documents separated by "---", each its own policy
// with its own annotation. Every annotation in the file is read: returning at the
// first one silently dropped the control mapping of every later document, which
// looks identical to that policy simply not being mapped.
func ExtractControlIDs(doc []byte) []string {
	var ids []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(doc), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, annotationKey) {
			continue
		}
		value := strings.TrimSpace(trimmed[len(annotationKey):])
		value = strings.Trim(value, "\"'")
		for _, part := range strings.Split(value, ",") {
			id := strings.TrimSpace(part)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// ControlsByPolicy scans policiesDir/kyverno/*.yaml and returns a map from each
// policy name (the file's base name without extension, which matches the
// ClusterPolicy metadata.name a PolicyReport references) to the control ids it
// annotates with fabric.control-id. Policies without the annotation are omitted.
// A missing kyverno directory yields an empty map, not an error.
func ControlsByPolicy(policiesDir string) (map[string][]string, error) {
	// Listed rather than globbed. filepath.Glob treats the DIRECTORY part of its
	// pattern as a pattern too, so a perfectly ordinary path containing a glob
	// metacharacter — a Jenkins workspace like "workspace[1]" is the usual way to
	// meet this — matches nothing and returns (nil, nil). That is a green
	// traceability check that verified no policies at all.
	kyvernoDir := filepath.Join(policiesDir, "kyverno")
	entries, err := os.ReadDir(kyvernoDir)
	if os.IsNotExist(err) {
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		matches = append(matches, filepath.Join(kyvernoDir, e.Name()))
	}
	sort.Strings(matches)

	out := make(map[string][]string)
	for _, path := range matches {
		doc, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if ids := ExtractControlIDs(doc); len(ids) > 0 {
			name := strings.TrimSuffix(filepath.Base(path), ".yaml")
			out[name] = ids
		}
	}
	return out, nil
}

// Verify checks that every Kyverno-backed control mapping in the bundle is
// realized by a policy file under policiesDir/kyverno/<policyID>.yaml whose
// fabric.control-id annotation includes the mapped control. Non-Kyverno
// components (for example the evidence ledger) are ignored.
func Verify(b validate.Bundle, policiesDir string) []validate.Finding {
	var findings []validate.Finding
	for _, cd := range b.ComponentDefinitions {
		for _, cp := range cd.ControlPolicies() {
			if cp.Component != "kyverno" || cp.PolicyID == "" {
				continue
			}
			path := filepath.Join(policiesDir, "kyverno", cp.PolicyID+".yaml")
			doc, err := os.ReadFile(path)
			if err != nil {
				findings = append(findings, validate.Finding{
					Rule:      "missing-policy",
					Severity:  validate.Error,
					ControlID: cp.ControlID,
					Message:   "no Kyverno policy file at " + path + " for policy " + cp.PolicyID,
				})
				continue
			}
			if !contains(ExtractControlIDs(doc), cp.ControlID) {
				findings = append(findings, validate.Finding{
					Rule:      "policy-control-id-mismatch",
					Severity:  validate.Error,
					ControlID: cp.ControlID,
					Message:   "policy " + cp.PolicyID + " does not annotate control " + cp.ControlID,
				})
			}
		}
	}
	return findings
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
