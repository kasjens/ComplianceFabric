package policies

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kasjens/ComplianceFabric/internal/validate"
)

const annotationKey = "fabric.control-id:"

// ExtractControlIDs scans a Kyverno policy document for the fabric.control-id
// annotation and returns the control IDs it declares. The value may be a single
// ID or a quoted, comma-separated list. Returns nil when the annotation is absent.
func ExtractControlIDs(doc []byte) []string {
	for _, line := range strings.Split(string(doc), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, annotationKey) {
			continue
		}
		value := strings.TrimSpace(trimmed[len(annotationKey):])
		value = strings.Trim(value, "\"'")
		var ids []string
		for _, part := range strings.Split(value, ",") {
			if id := strings.TrimSpace(part); id != "" {
				ids = append(ids, id)
			}
		}
		return ids
	}
	return nil
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
