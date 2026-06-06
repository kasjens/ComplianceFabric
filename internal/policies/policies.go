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
		for _, m := range cd.Mappings {
			for _, impl := range m.ImplementedBy {
				if impl.Component != "kyverno" {
					continue
				}
				path := filepath.Join(policiesDir, "kyverno", impl.PolicyID+".yaml")
				doc, err := os.ReadFile(path)
				if err != nil {
					findings = append(findings, validate.Finding{
						Rule:      "missing-policy",
						Severity:  validate.Error,
						ControlID: m.ControlID,
						Message:   "no Kyverno policy file at " + path + " for policy " + impl.PolicyID,
					})
					continue
				}
				if !contains(ExtractControlIDs(doc), m.ControlID) {
					findings = append(findings, validate.Finding{
						Rule:      "policy-control-id-mismatch",
						Severity:  validate.Error,
						ControlID: m.ControlID,
						Message:   "policy " + impl.PolicyID + " does not annotate control " + m.ControlID,
					})
				}
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
