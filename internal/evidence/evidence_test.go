package evidence

import (
	"strings"
	"testing"
	"time"
)

// mergedPR is a gh pr view --json record for an approved, merged pull request.
const mergedPR = `{
  "number": 42,
  "title": "Add Sigstore image verification",
  "url": "https://github.com/kasjens/ComplianceFabric/pull/42",
  "state": "MERGED",
  "author": { "login": "kasjens" },
  "mergedAt": "2026-06-05T14:30:00Z",
  "mergeCommit": { "oid": "32fa9af0c0ffee" },
  "reviews": [
    { "author": { "login": "reviewer-a" }, "state": "COMMENTED" },
    { "author": { "login": "reviewer-a" }, "state": "APPROVED" },
    { "author": { "login": "reviewer-b" }, "state": "APPROVED" }
  ]
}`

func TestExtractReadsChangeControlFields(t *testing.T) {
	rec, err := Extract([]byte(mergedPR))
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if rec.Number != 42 {
		t.Errorf("Number = %d, want 42", rec.Number)
	}
	if rec.Author != "kasjens" {
		t.Errorf("Author = %q, want kasjens", rec.Author)
	}
	if rec.MergeCommit != "32fa9af0c0ffee" {
		t.Errorf("MergeCommit = %q, want 32fa9af0c0ffee", rec.MergeCommit)
	}
	want := time.Date(2026, 6, 5, 14, 30, 0, 0, time.UTC)
	if !rec.MergedAt.Equal(want) {
		t.Errorf("MergedAt = %v, want %v", rec.MergedAt, want)
	}
	if len(rec.Approvers) != 2 {
		t.Fatalf("Approvers = %v, want two distinct approvers", rec.Approvers)
	}
	if rec.Approvers[0] != "reviewer-a" || rec.Approvers[1] != "reviewer-b" {
		t.Errorf("Approvers = %v, want [reviewer-a reviewer-b]", rec.Approvers)
	}
}

// openPR is an unmerged, unreviewed pull request.
const openPR = `{
  "number": 7,
  "title": "WIP: experiment",
  "url": "https://github.com/kasjens/ComplianceFabric/pull/7",
  "state": "OPEN",
  "author": { "login": "kasjens" },
  "mergedAt": null,
  "mergeCommit": null,
  "reviews": []
}`

func TestIssuesEmptyForValidAuthorizedChange(t *testing.T) {
	rec, err := Extract([]byte(mergedPR))
	if err != nil {
		t.Fatal(err)
	}
	if issues := rec.Issues(); len(issues) != 0 {
		t.Fatalf("expected no issues for a merged, approved PR, got %v", issues)
	}
}

func TestIssuesFlagsUnmergedUnapprovedChange(t *testing.T) {
	rec, err := Extract([]byte(openPR))
	if err != nil {
		t.Fatal(err)
	}
	issues := rec.Issues()
	if len(issues) == 0 {
		t.Fatal("expected an open, unapproved PR to be flagged as not a valid authorized change")
	}
	joined := strings.Join(issues, "; ")
	if !strings.Contains(joined, "not merged") {
		t.Errorf("expected an issue about merge state, got %v", issues)
	}
	if !strings.Contains(joined, "no approval") {
		t.Errorf("expected an issue about missing approval, got %v", issues)
	}
}

func TestExtractDeduplicatesRepeatedApprover(t *testing.T) {
	rec, err := Extract([]byte(mergedPR))
	if err != nil {
		t.Fatal(err)
	}
	for i := range rec.Approvers {
		for j := i + 1; j < len(rec.Approvers); j++ {
			if rec.Approvers[i] == rec.Approvers[j] {
				t.Fatalf("approver %q listed twice: %v", rec.Approvers[i], rec.Approvers)
			}
		}
	}
}
