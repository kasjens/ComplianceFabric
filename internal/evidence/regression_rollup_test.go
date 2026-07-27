package evidence

import (
	"testing"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

// 3.4 — the Kyverno timestamp is an OPTIONAL field. When it is absent,
// res.Timestamp.Seconds is the zero value and time.Unix(0,0) yields 1970, which
// is not IsZero(), so nothing downstream can tell an imputed timestamp from a
// real one. The record silently claims to have been observed in 1970.
func TestMissingPolicyReportTimestampMustNotBecomeEpoch(t *testing.T) {
	report := []byte(`{
	  "scope": {"kind":"Pod","namespace":"prod","name":"api"},
	  "results": [
	    {"policy":"require-signed-images","result":"fail",
	     "resources":[{"kind":"Pod","namespace":"prod","name":"api"}]}
	  ]
	}`)
	controls := map[string][]string{"require-signed-images": {"cfr-part-11-10a-system-validation"}}

	records, err := FromPolicyReport(report, controls)
	if err != nil {
		// Refusing a result with no timestamp is an acceptable fix.
		return
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	got := records[0].ObservedAt
	if got.Year() < 2000 {
		t.Errorf("a policy-report result with no timestamp produced observed-at %s; "+
			"an imputed timestamp must be either rejected or marked, never presented "+
			"as a real 1970 observation (it also sorts to the front of every trend)",
			got.Format(time.RFC3339))
	}
}

// 3.5 — the gateway writes TWO log lines per interaction (phase "input" and phase
// "output") sharing one id, but traceRec has no `phase` field and the subject is
// built from the agent and id alone. One interaction therefore becomes TWO
// evidence records with an identical subject, inflating auditor-facing counts
// ~2x. Worse, a guardrail-blocked OUTPUT yields both a satisfied record (the
// input passed) and a not-satisfied one for the same interaction.
func TestOneInteractionMustYieldOneRecord(t *testing.T) {
	reg := registry.Registry{Agents: []registry.Agent{{
		ID:      "release-reviewer",
		Prompts: []string{"summarise-findings"},
	}}}

	// Exactly what Proxy.ServeHTTP writes for a single interaction whose output
	// the guardrail blocked.
	log := []byte(`{"id":"i-1","agent":"release-reviewer","prompt":"summarise-findings","phase":"input","allowed":true,"timestamp":"2026-07-01T10:00:00Z"}
{"id":"i-1","agent":"release-reviewer","prompt":"summarise-findings","phase":"output","allowed":false,"timestamp":"2026-07-01T10:00:01Z"}`)

	records, err := FromAgentTraces(log, reg, "annex11-12-security")
	if err != nil {
		t.Fatalf("FromAgentTraces: %v", err)
	}

	if len(records) != 1 {
		t.Errorf("one interaction produced %d evidence records (subjects: %s); "+
			"auditor-facing counts are inflated and the input/output phases are "+
			"indistinguishable", len(records), subjectsOf(records))
	}

	// Whatever the count, the interaction must not be reported as satisfied when
	// its output was blocked.
	for _, r := range records {
		if r.Result == oscal.StatusSatisfied {
			t.Errorf("interaction i-1 produced a SATISFIED record even though the "+
				"gateway blocked its output (subject %q)", r.Subject)
		}
	}
}

func subjectsOf(records []Record) string {
	out := ""
	for i, r := range records {
		if i > 0 {
			out += ", "
		}
		out += r.Subject
	}
	return out
}
