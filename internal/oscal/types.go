// Package oscal holds a minimal, JSON-serializable subset of the OSCAL models
// the Fabric works with: catalogs, profiles, and component definitions.
//
// The shapes follow the project's own documented examples in
// docs/02-control-authoring.md rather than the full NIST OSCAL schema. They are
// deliberately small; tests drive what gets added.
package oscal

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

// ComponentDefinition maps controls to the technical policies that implement them.
type ComponentDefinition struct {
	Metadata Metadata  `json:"metadata"`
	Mappings []Mapping `json:"mappings"`
}

// Mapping ties one control to the policies that satisfy it. The shape mirrors
// the example in docs/02-control-authoring.md.
type Mapping struct {
	ControlID     string           `json:"control-id"`
	Description   string           `json:"description"`
	ImplementedBy []Implementation `json:"implemented-by"`
}

// Implementation names a component and the policy identifier within it.
type Implementation struct {
	Component string `json:"component"`
	PolicyID  string `json:"policy-id"`
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
