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
	ControlID  string       `json:"control-id"`
	Subject    string       `json:"subject"`
	Result     string       `json:"result"`
	ObservedAt time.Time    `json:"observed-at"`
	Source     string       `json:"source"`
	Change     ChangeRecord `json:"change"`
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
		Change:     r,
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
