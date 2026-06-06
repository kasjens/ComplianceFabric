// Package validate checks the integrity of an OSCAL control bundle: that
// profiles, catalogs, and component definitions agree with one another. A wrong
// mapping produces wrong evidence, so these checks run before anything is
// compiled into policy.
package validate

import (
	"strconv"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// Bundle is the set of OSCAL documents validated together.
type Bundle struct {
	Catalogs             []oscal.Catalog
	Profiles             []oscal.Profile
	ComponentDefinitions []oscal.ComponentDefinition
}

// Severity classifies a finding.
type Severity string

const (
	Error Severity = "error"
)

// Finding is one problem discovered during validation.
type Finding struct {
	Rule      string
	Severity  Severity
	ControlID string
	Message   string
}

// Run validates the bundle and returns every finding. An empty slice means the
// bundle is internally consistent.
func Run(b Bundle) []Finding {
	var findings []Finding
	findings = append(findings, checkProfileControlsResolve(b)...)
	findings = append(findings, checkMappingControlsResolve(b)...)
	findings = append(findings, checkNoDuplicateControlIDs(b)...)
	findings = append(findings, checkProfileCoverage(b)...)
	findings = append(findings, checkMappingBindings(b)...)
	return findings
}

// checkNoDuplicateControlIDs flags a control ID that appears more than once
// within the same catalog. Each duplicated ID is reported once.
func checkNoDuplicateControlIDs(b Bundle) []Finding {
	var findings []Finding
	for _, cat := range b.Catalogs {
		seen := make(map[string]int, len(cat.Controls))
		for _, c := range cat.Controls {
			seen[c.ID]++
		}
		for id, n := range seen {
			if n > 1 {
				findings = append(findings, Finding{
					Rule:      "duplicate-control-id",
					Severity:  Error,
					ControlID: id,
					Message:   "control " + id + " is defined " + strconv.Itoa(n) + " times in catalog " + cat.ID,
				})
			}
		}
	}
	return findings
}

// checkProfileCoverage flags any control a profile selects that no component
// definition maps to a policy. An uncovered control is authored intent with no
// enforcement behind it.
func checkProfileCoverage(b Bundle) []Finding {
	mapped := make(map[string]bool)
	for _, cd := range b.ComponentDefinitions {
		for _, m := range cd.Mappings {
			mapped[m.ControlID] = true
		}
	}

	var findings []Finding
	for _, prof := range b.Profiles {
		for _, imp := range prof.Imports {
			for _, id := range imp.IncludeControls {
				if !mapped[id] {
					findings = append(findings, Finding{
						Rule:      "uncovered-control",
						Severity:  Error,
						ControlID: id,
						Message:   "profile selects control " + id + " but no component definition maps it to a policy",
					})
				}
			}
		}
	}
	return findings
}

// checkMappingBindings flags mappings with no implementations and any
// implementation missing a component or policy ID.
func checkMappingBindings(b Bundle) []Finding {
	var findings []Finding
	for _, cd := range b.ComponentDefinitions {
		for _, m := range cd.Mappings {
			if len(m.ImplementedBy) == 0 {
				findings = append(findings, Finding{
					Rule:      "empty-mapping",
					Severity:  Error,
					ControlID: m.ControlID,
					Message:   "control " + m.ControlID + " has a mapping with no implementations",
				})
				continue
			}
			for _, impl := range m.ImplementedBy {
				if impl.Component == "" || impl.PolicyID == "" {
					findings = append(findings, Finding{
						Rule:      "incomplete-binding",
						Severity:  Error,
						ControlID: m.ControlID,
						Message:   "control " + m.ControlID + " has an implementation missing a component or policy-id",
					})
				}
			}
		}
	}
	return findings
}

// allControlIDs returns the set of every control ID defined across all catalogs.
func allControlIDs(b Bundle) map[string]bool {
	ids := make(map[string]bool)
	for _, cat := range b.Catalogs {
		for _, c := range cat.Controls {
			ids[c.ID] = true
		}
	}
	return ids
}

// checkMappingControlsResolve verifies every control a component definition maps
// is a real control defined in some catalog.
func checkMappingControlsResolve(b Bundle) []Finding {
	known := allControlIDs(b)
	var findings []Finding
	for _, cd := range b.ComponentDefinitions {
		for _, m := range cd.Mappings {
			if !known[m.ControlID] {
				findings = append(findings, Finding{
					Rule:      "unmapped-control",
					Severity:  Error,
					ControlID: m.ControlID,
					Message:   "component definition maps control " + m.ControlID + " not defined in any catalog",
				})
			}
		}
	}
	return findings
}

// checkProfileControlsResolve verifies every control a profile selects exists in
// the catalog the import points to.
func checkProfileControlsResolve(b Bundle) []Finding {
	controlsByCatalog := make(map[string]map[string]bool, len(b.Catalogs))
	for _, cat := range b.Catalogs {
		ids := make(map[string]bool, len(cat.Controls))
		for _, c := range cat.Controls {
			ids[c.ID] = true
		}
		controlsByCatalog[cat.ID] = ids
	}

	var findings []Finding
	for _, prof := range b.Profiles {
		for _, imp := range prof.Imports {
			ids, ok := controlsByCatalog[imp.Href]
			if !ok {
				findings = append(findings, Finding{
					Rule:     "unresolved-catalog",
					Severity: Error,
					Message:  "profile import references unknown catalog " + imp.Href,
				})
				continue
			}
			for _, id := range imp.IncludeControls {
				if !ids[id] {
					findings = append(findings, Finding{
						Rule:      "unresolved-control",
						Severity:  Error,
						ControlID: id,
						Message:   "profile selects control " + id + " not present in catalog " + imp.Href,
					})
				}
			}
		}
	}
	return findings
}
