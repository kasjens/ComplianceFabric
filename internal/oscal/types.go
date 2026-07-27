// Package oscal holds a minimal, JSON-serializable subset of the OSCAL models
// the Fabric works with: catalogs, profiles, and component definitions.
//
// The shapes follow the project's own documented examples in
// docs/02-control-authoring.md rather than the full NIST OSCAL schema. They are
// deliberately small; tests drive what gets added.
package oscal

import "sort"

// Metadata is the small descriptive header shared by every OSCAL document.
type Metadata struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

// Catalog is the full set of control statements for a framework. ID is the
// logical identifier a profile import references via its Href.
type Catalog struct {
	ID       string    `json:"id"`
	Metadata Metadata  `json:"metadata"`
	Controls []Control `json:"controls"`
}

// Control is a single control statement.
type Control struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Statement string `json:"statement,omitempty"`
}

// Profile selects and tailors the controls that apply to a given system.
type Profile struct {
	Metadata Metadata `json:"metadata"`
	Imports  []Import `json:"imports"`
}

// Import pulls controls from a catalog into a profile by ID.
type Import struct {
	Href            string   `json:"href"`
	IncludeControls []string `json:"include-controls"`
}

// ComponentDefinition describes the components that implement controls. It
// follows the OSCAL rule_set convention used by Compliance-to-Policy: a
// component declares rules as grouped props, and each implemented-requirement
// references those rules by Rule_Id. This lets the same source feed C2P later
// without reshaping.
type ComponentDefinition struct {
	Metadata   Metadata    `json:"metadata"`
	Components []Component `json:"components"`
}

// Component is one technical component (for example the Kyverno engine). Its
// Title is the component name the rest of the Fabric matches on. Props carry
// rule_set definitions; ControlImplementations bind controls to those rules.
type Component struct {
	Title                  string                  `json:"title"`
	Type                   string                  `json:"type,omitempty"`
	Description            string                  `json:"description,omitempty"`
	Props                  []Prop                  `json:"props,omitempty"`
	ControlImplementations []ControlImplementation `json:"control-implementations"`
}

// Prop is an OSCAL property. Rule sets are expressed as props sharing a Remarks
// group key (for example "rule_set_00") with names Rule_Id, Rule_Description,
// Check_Id, and Check_Description.
type Prop struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Class   string `json:"class,omitempty"`
	Remarks string `json:"remarks,omitempty"`
}

// ControlImplementation binds a set of controls (from Source) to the rules a
// component provides.
type ControlImplementation struct {
	Source                  string                   `json:"source"`
	Description             string                   `json:"description,omitempty"`
	ImplementedRequirements []ImplementedRequirement `json:"implemented-requirements"`
}

// ImplementedRequirement states that a control is satisfied by one or more
// rules, named via Rule_Id props.
type ImplementedRequirement struct {
	ControlID   string `json:"control-id"`
	Description string `json:"description,omitempty"`
	Props       []Prop `json:"props,omitempty"`
}

// ControlPolicy is the resolved (control, component, check) triple the rest of
// the engine enforces against, after following each Rule_Id to its Check_Id.
type ControlPolicy struct {
	ControlID string
	Component string
	PolicyID  string
}

// RuleRef identifies a Rule_Id referenced by a control's implemented-requirement.
type RuleRef struct {
	ControlID string
	Component string
	RuleID    string
}

// ruleChecks maps each Rule_Id declared on the component to its Check_Id, by
// grouping props on their shared Remarks (rule_set) key. A rule set without a
// Check_Id yields an empty string so callers can flag it.
func (c Component) ruleChecks() map[string]string {
	groupRule := map[string]string{}
	groupCheck := map[string]string{}
	for _, p := range c.Props {
		switch p.Name {
		case "Rule_Id":
			groupRule[p.Remarks] = p.Value
		case "Check_Id":
			groupCheck[p.Remarks] = p.Value
		}
	}
	// Resolve in a deterministic order. Iterating groupRule directly meant that
	// when two rule-set groups declared the SAME Rule_Id with different Check_Ids,
	// which one won depended on Go's randomised map iteration - so `fabric
	// generate` composed a different policy set from byte-identical inputs.
	// Duplicates remain a defect in the source data (DuplicateRuleIDs reports
	// them); resolving them by lowest group key at least makes output
	// reproducible.
	groups := make([]string, 0, len(groupRule))
	for group := range groupRule {
		groups = append(groups, group)
	}
	sort.Strings(groups)

	checks := map[string]string{}
	assignedBy := map[string]string{}
	for _, group := range groups {
		rule := groupRule[group]
		if _, taken := checks[rule]; taken && assignedBy[rule] <= group {
			continue
		}
		checks[rule] = groupCheck[group]
		assignedBy[rule] = group
	}
	return checks
}

// DuplicateRuleIDs returns every Rule_Id the component declares more than once,
// sorted. A duplicate is ambiguous by construction: two rule sets claim the same
// rule name with potentially different checks, so the composed policy set depends
// on which declaration wins. Callers should reject a component that reports any.
func (c Component) DuplicateRuleIDs() []string {
	counts := map[string]int{}
	for _, p := range c.Props {
		if p.Name == "Rule_Id" {
			counts[p.Value]++
		}
	}
	var dupes []string
	for rule, n := range counts {
		if n > 1 {
			dupes = append(dupes, rule)
		}
	}
	sort.Strings(dupes)
	return dupes
}

// ControlPolicies resolves every control's Rule_Id references down to the
// concrete check (policy) that enforces it. References to a known rule with no
// Check_Id produce a triple with an empty PolicyID; references to an unknown
// rule are omitted here and surfaced by UnresolvedRules.
func (cd ComponentDefinition) ControlPolicies() []ControlPolicy {
	var out []ControlPolicy
	for _, comp := range cd.Components {
		checks := comp.ruleChecks()
		for _, ci := range comp.ControlImplementations {
			for _, req := range ci.ImplementedRequirements {
				for _, ruleID := range ruleIDs(req.Props) {
					check, known := checks[ruleID]
					if !known {
						continue
					}
					out = append(out, ControlPolicy{
						ControlID: req.ControlID,
						Component: comp.Title,
						PolicyID:  check,
					})
				}
			}
		}
	}
	return out
}

// UnresolvedRules returns control rule references whose Rule_Id is not defined
// in the component's rule sets.
func (cd ComponentDefinition) UnresolvedRules() []RuleRef {
	var out []RuleRef
	for _, comp := range cd.Components {
		checks := comp.ruleChecks()
		for _, ci := range comp.ControlImplementations {
			for _, req := range ci.ImplementedRequirements {
				for _, ruleID := range ruleIDs(req.Props) {
					if _, known := checks[ruleID]; !known {
						out = append(out, RuleRef{
							ControlID: req.ControlID,
							Component: comp.Title,
							RuleID:    ruleID,
						})
					}
				}
			}
		}
	}
	return out
}

func ruleIDs(props []Prop) []string {
	var ids []string
	for _, p := range props {
		if p.Name == "Rule_Id" {
			ids = append(ids, p.Value)
		}
	}
	return ids
}

// AssessmentResults is the OSCAL model that records the outcome of assessing a
// system against its controls. The Fabric emits one so evidence and reports can
// be traced back to the control each result satisfies.
type AssessmentResults struct {
	Metadata Metadata `json:"metadata"`
	Results  []Result `json:"results"`
}

// Result groups the findings from one assessment run.
type Result struct {
	Title    string              `json:"title"`
	Findings []AssessmentFinding `json:"findings"`
}

// AssessmentFinding records the status of one control. Status follows OSCAL:
// "satisfied" or "not-satisfied".
type AssessmentFinding struct {
	ControlID string `json:"control-id"`
	Status    string `json:"status"`
	Statement string `json:"statement"`
}

// Assessment status values.
const (
	StatusSatisfied    = "satisfied"
	StatusNotSatisfied = "not-satisfied"
)
