// Package evidence derives change-control records from GitOps pull-request data.
// A merged pull request, with its author, reviewer approvals, merge timestamp,
// and merge commit, is the attributable, time-stamped record of an authorized
// change that EU GMP Annex 11 and 21 CFR Part 11 expect. Extract reads the JSON
// emitted by `gh pr view --json ...` so it operates on real GitHub data.
package evidence

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// ChangeRecord is the change-control evidence distilled from one pull request.
type ChangeRecord struct {
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	URL         string    `json:"url"`
	Author      string    `json:"author"`
	State       string    `json:"state"`
	Approvers   []string  `json:"approvers"`
	MergedAt    time.Time `json:"merged-at"`
	MergeCommit string    `json:"merge-commit"`
}

// Issues returns the reasons this record is not a valid, attributable
// change-control authorization. An empty result means the change is authorized:
// merged, attributable to an author, reviewer-approved, and bound to a merge
// commit and timestamp. A non-empty result is what a reviewer flags.
func (r ChangeRecord) Issues() []string {
	var issues []string
	if r.State != "MERGED" {
		issues = append(issues, "change is not merged")
	}
	if r.Author == "" {
		issues = append(issues, "change has no attributable author")
	}
	if len(r.Approvers) == 0 {
		issues = append(issues, "change has no approval")
	}
	if r.MergeCommit == "" {
		issues = append(issues, "change has no merge commit")
	}
	if r.MergedAt.IsZero() {
		issues = append(issues, "change has no merge timestamp")
	}
	return issues
}

// Record is an evidence-ledger entry keyed to a control id, following the data
// model in docs/07-evidence-and-audit.md. It carries the embedded change record
// as the raw evidence behind the result.
type Record struct {
	ControlID  string    `json:"control-id"`
	Subject    string    `json:"subject"`
	Result     string    `json:"result"`
	ObservedAt time.Time `json:"observed-at"`
	Source     string    `json:"source"`
	// ArtifactRef, when set, points at the artifact this record concerns by its
	// content digest (for example "sha256:1f2e..."). It lets a reviewer pivot from
	// an evidence record to the exact built artifact - and, since the digest is
	// what a transparency log (Rekor) indexes, to that artifact's transparency-log
	// entry. Records that do not concern a specific artifact leave it empty.
	ArtifactRef string        `json:"artifact-ref,omitempty"`
	Change      *ChangeRecord `json:"change,omitempty"`
}

// AsEvidence turns a change-control record into an evidence-ledger entry for the
// given control id. The result is "satisfied" when the change is a valid
// authorized change (Issues is empty) and "not-satisfied" otherwise. ObservedAt
// is the merge timestamp, the authoritative time the change was authorized.
func (r ChangeRecord) AsEvidence(controlID string) Record {
	result := oscal.StatusSatisfied
	if len(r.Issues()) > 0 {
		result = oscal.StatusNotSatisfied
	}
	return Record{
		ControlID:  controlID,
		Subject:    fmt.Sprintf("commit/%s", r.MergeCommit),
		Result:     result,
		ObservedAt: r.MergedAt,
		Source:     fmt.Sprintf("github/pull-request#%d", r.Number),
		Change:     &r,
	}
}

// AsFinding turns an evidence record into an OSCAL assessment finding, carrying
// the control id and observed result through unchanged and summarizing where the
// evidence came from in the statement.
func (r Record) AsFinding() oscal.AssessmentFinding {
	return oscal.AssessmentFinding{
		ControlID: r.ControlID,
		Status:    r.Result,
		Statement: fmt.Sprintf("observed %s from %s at %s", r.Subject, r.Source, r.ObservedAt.Format(time.RFC3339)),
	}
}

// AssessmentResults normalizes a set of evidence records into an OSCAL
// assessment-results document: one finding per record, each tracing back to the
// control it bears on. This is the form an audit pack or posture view queries,
// and it is the same model fabric assess emits, so evidence and design-time
// coverage share one shape.
func AssessmentResults(records []Record) oscal.AssessmentResults {
	findings := make([]oscal.AssessmentFinding, 0, len(records))
	for _, rec := range records {
		findings = append(findings, rec.AsFinding())
	}
	return oscal.AssessmentResults{
		Metadata: oscal.Metadata{
			Title:   "Evidence-based control assessment",
			Version: "0.1.0",
		},
		Results: []oscal.Result{{
			Title:    "Observed control evidence",
			Findings: findings,
		}},
	}
}

// Extract parses a `gh pr view --json` record into a ChangeRecord. Approvers are
// the distinct logins whose latest review state is APPROVED, in first-seen order.
func Extract(prJSON []byte) (ChangeRecord, error) {
	var pr struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		URL    string `json:"url"`
		State  string `json:"state"`
		Author struct {
			Login string `json:"login"`
		} `json:"author"`
		MergedAt    time.Time `json:"mergedAt"`
		MergeCommit struct {
			OID string `json:"oid"`
		} `json:"mergeCommit"`
		Reviews []struct {
			Author struct {
				Login string `json:"login"`
			} `json:"author"`
			State string `json:"state"`
		} `json:"reviews"`
	}
	if err := json.Unmarshal(prJSON, &pr); err != nil {
		return ChangeRecord{}, err
	}

	rec := ChangeRecord{
		Number:      pr.Number,
		Title:       pr.Title,
		URL:         pr.URL,
		State:       pr.State,
		Author:      pr.Author.Login,
		MergedAt:    pr.MergedAt,
		MergeCommit: pr.MergeCommit.OID,
	}
	seen := map[string]bool{}
	for _, r := range pr.Reviews {
		if r.State != "APPROVED" || seen[r.Author.Login] {
			continue
		}
		seen[r.Author.Login] = true
		rec.Approvers = append(rec.Approvers, r.Author.Login)
	}
	return rec, nil
}
