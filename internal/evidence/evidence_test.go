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

func TestAsEvidenceForValidChangeIsSatisfied(t *testing.T) {
	rec, err := Extract([]byte(mergedPR))
	if err != nil {
		t.Fatal(err)
	}
	ev := rec.AsEvidence("annex11-change-control")

	if ev.ControlID != "annex11-change-control" {
		t.Errorf("ControlID = %q, want annex11-change-control", ev.ControlID)
	}
	if ev.Result != "satisfied" {
		t.Errorf("Result = %q, want satisfied", ev.Result)
	}
	want := time.Date(2026, 6, 5, 14, 30, 0, 0, time.UTC)
	if !ev.ObservedAt.Equal(want) {
		t.Errorf("ObservedAt = %v, want %v (the merge time)", ev.ObservedAt, want)
	}
	if !strings.Contains(ev.Subject, "32fa9af0c0ffee") {
		t.Errorf("Subject = %q, want it to reference the merge commit", ev.Subject)
	}
	if !strings.Contains(ev.Source, "42") {
		t.Errorf("Source = %q, want it to reference the pull request", ev.Source)
	}
	if ev.Change.MergeCommit != "32fa9af0c0ffee" {
		t.Errorf("Change evidence not embedded: %+v", ev.Change)
	}
}

func TestAsEvidenceForFlaggedChangeIsNotSatisfied(t *testing.T) {
	rec, err := Extract([]byte(openPR))
	if err != nil {
		t.Fatal(err)
	}
	ev := rec.AsEvidence("annex11-change-control")
	if ev.Result != "not-satisfied" {
		t.Errorf("Result = %q, want not-satisfied for an unmerged, unapproved change", ev.Result)
	}
}

func TestAssessmentResultsMapsRecordsToFindings(t *testing.T) {
	merged, err := Extract([]byte(mergedPR))
	if err != nil {
		t.Fatal(err)
	}
	open, err := Extract([]byte(openPR))
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{
		merged.AsEvidence("annex11-10-change-control"),
		open.AsEvidence("annex11-10-change-control"),
	}

	ar := AssessmentResults(records)
	if len(ar.Results) != 1 {
		t.Fatalf("want one result group, got %d", len(ar.Results))
	}
	findings := ar.Results[0].Findings
	if len(findings) != 2 {
		t.Fatalf("want a finding per record, got %d", len(findings))
	}
	if findings[0].ControlID != "annex11-10-change-control" {
		t.Errorf("finding control id = %q, want annex11-10-change-control", findings[0].ControlID)
	}
	if findings[0].Status != "satisfied" {
		t.Errorf("merged change finding status = %q, want satisfied", findings[0].Status)
	}
	if findings[1].Status != "not-satisfied" {
		t.Errorf("open change finding status = %q, want not-satisfied", findings[1].Status)
	}
	if !strings.Contains(findings[0].Statement, "github/pull-request#42") {
		t.Errorf("finding statement %q should reference the evidence source", findings[0].Statement)
	}
}

func TestAssessmentResultsEmptyForNoRecords(t *testing.T) {
	ar := AssessmentResults(nil)
	if len(ar.Results) != 1 {
		t.Fatalf("want one result group even when empty, got %d", len(ar.Results))
	}
	if len(ar.Results[0].Findings) != 0 {
		t.Errorf("want no findings for no records, got %d", len(ar.Results[0].Findings))
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
