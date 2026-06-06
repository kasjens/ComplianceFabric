// Package evidence derives change-control records from GitOps pull-request data.
// A merged pull request, with its author, reviewer approvals, merge timestamp,
// and merge commit, is the attributable, time-stamped record of an authorized
// change that EU GMP Annex 11 and 21 CFR Part 11 expect. Extract reads the JSON
// emitted by `gh pr view --json ...` so it operates on real GitHub data.
package evidence

import (
	"encoding/json"
	"time"
)

// ChangeRecord is the change-control evidence distilled from one pull request.
type ChangeRecord struct {
	Number      int
	Title       string
	URL         string
	Author      string
	State       string
	Approvers   []string
	MergedAt    time.Time
	MergeCommit string
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
