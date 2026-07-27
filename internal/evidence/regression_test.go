package evidence

import (
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

// merged returns an otherwise-valid merged change record, so that the only thing
// under test is the approval relationship.
func merged(author string, approvers ...string) ChangeRecord {
	return ChangeRecord{
		Number:      7,
		Title:       "raise batch-release limit",
		URL:         "https://example/pr/7",
		State:       "MERGED",
		Author:      author,
		Approvers:   approvers,
		MergeCommit: "abc123",
		MergedAt:    time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC),
	}
}

// 3.1 — Issues() counts approvers but never compares them to the author, so a PR
// its own author approved is recorded as satisfied change control. Segregation of
// duties is the entire point of the control under Annex 11 and Part 11.
func TestSelfApprovalIsNotChangeControl(t *testing.T) {
	cases := []struct {
		name           string
		rec            ChangeRecord
		wantAuthorized bool
	}{
		{"self-approval only", merged("alice", "alice"), false},
		{"self-approval, case-differing login", merged("Alice", "alice"), false},
		{"self plus an independent approver", merged("alice", "alice", "bob"), true},
		{"independent approver only", merged("alice", "bob"), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAuthorized := len(tc.rec.Issues()) == 0
			if gotAuthorized != tc.wantAuthorized {
				t.Errorf("Issues(): authorized=%v, want %v (author=%q approvers=%v)",
					gotAuthorized, tc.wantAuthorized, tc.rec.Author, tc.rec.Approvers)
			}

			want := oscal.StatusNotSatisfied
			if tc.wantAuthorized {
				want = oscal.StatusSatisfied
			}
			if got := tc.rec.AsEvidence("annex11-10-change-control").Result; got != want {
				t.Errorf("AsEvidence: minted %q evidence for annex11-10-change-control, want %q", got, want)
			}
		})
	}
}

// 3.2 — Extract documents "the distinct logins whose LATEST review state is
// APPROVED", but the loop takes the FIRST state per login and skips the rest, so
// an approval that was later withdrawn still counts.
func TestWithdrawnApprovalMustNotCount(t *testing.T) {
	cases := []struct {
		name         string
		reviews      string
		wantApprover bool
	}{
		{
			name:         "approve then request changes",
			reviews:      `{"author":{"login":"bob"},"state":"APPROVED"},{"author":{"login":"bob"},"state":"CHANGES_REQUESTED"}`,
			wantApprover: false,
		},
		{
			name:         "request changes then approve",
			reviews:      `{"author":{"login":"bob"},"state":"CHANGES_REQUESTED"},{"author":{"login":"bob"},"state":"APPROVED"}`,
			wantApprover: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prJSON := []byte(`{
			  "number": 7, "title": "t", "url": "u", "state": "MERGED",
			  "author": {"login":"alice"},
			  "mergedAt": "2026-07-01T10:00:00Z",
			  "mergeCommit": {"oid":"abc123"},
			  "reviews": [` + tc.reviews + `]
			}`)

			rec, err := Extract(prJSON)
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}

			isApprover := false
			for _, a := range rec.Approvers {
				if a == "bob" {
					isApprover = true
				}
			}
			if isApprover != tc.wantApprover {
				t.Errorf("bob counted as approver=%v, want %v (approvers=%v)",
					isApprover, tc.wantApprover, rec.Approvers)
			}
		})
	}
}
