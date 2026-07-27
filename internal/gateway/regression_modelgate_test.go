package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

// pinnedRegistry qualifies an agent that may ONLY use "approved-model".
func pinnedRegistry() registry.Registry {
	return registry.Registry{
		Agents: []registry.Agent{{
			ID:      "release-reviewer",
			Model:   "approved-model",
			Prompts: []string{"summarise-findings"},
		}},
	}
}

func extract(t *testing.T, body string) Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "http://upstream/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(HeaderAgent, "release-reviewer")
	r.Header.Set(HeaderPrompt, "summarise-findings")

	req, err := RequestFromHTTP(r)
	if err != nil {
		t.Fatalf("RequestFromHTTP: %v", err)
	}
	return req
}

// 1.7(b) — encoding/json matches object keys CASE-INSENSITIVELY and takes the
// LAST match. A body carrying both "model" and "Model" therefore shows the
// gateway one value while a strict upstream parser reads the other, so the model
// allow-list is decided on a different value than the one that will be served.
func TestCaseVariantDuplicateKeyMustBeRejected(t *testing.T) {
	// The gateway sees "approved-model" (last match wins) and allows;
	// a strict upstream taking the first "model" key serves "forbidden-model".
	const body = `{"model":"forbidden-model","Model":"approved-model",
	               "messages":[{"role":"user","content":"go"}]}`

	r, err := http.NewRequest(http.MethodPost, "http://upstream/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(HeaderAgent, "release-reviewer")
	r.Header.Set(HeaderPrompt, "summarise-findings")

	req, err := RequestFromHTTP(r)
	if err != nil {
		return // rejecting the ambiguous body is the desired behaviour
	}

	if d := Decide(pinnedRegistry(), req); d.Allowed {
		t.Errorf("a body declaring both \"model\":%q and \"Model\":%q was ALLOWED; "+
			"the gateway gated on %q while a strict upstream would serve the other",
			"forbidden-model", "approved-model", req.Model)
	}
}

// 1.7(a) — the model gate carves out req.Model == "". Azure OpenAI takes the
// deployment from the URL PATH, so a request that omits the body "model" still
// reaches a real model — while skipping the allow-list entirely.
func TestMissingModelWithPinnedAgentMustDeny(t *testing.T) {
	req := extract(t, `{"messages":[{"role":"user","content":"go"}]}`)

	if req.Model != "" {
		t.Fatalf("precondition: expected an empty model, got %q", req.Model)
	}
	if d := Decide(pinnedRegistry(), req); d.Allowed {
		t.Error("an agent pinned to \"approved-model\" was allowed to send a request " +
			"declaring NO model; the allow-list was skipped rather than enforced")
	}
}

// 1.7 — legacy OpenAI "functions" are not extracted, so tool qualification is
// skipped for callers using the older shape.
func TestLegacyFunctionsMustBeExtracted(t *testing.T) {
	req := extract(t, `{"model":"approved-model","messages":[],
	                    "functions":[{"name":"exfiltrate"}]}`)

	found := false
	for _, tool := range req.Tools {
		if tool == "exfiltrate" {
			found = true
		}
	}
	if !found {
		t.Errorf("legacy OpenAI \"functions\" were not extracted as tools (got %v); "+
			"tool qualification is skipped entirely for this shape", req.Tools)
	}
}
