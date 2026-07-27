package gateway

import (
	"net/http"
	"strings"
	"testing"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

// secret matches the guardrail rule the project ships.
const secret = "AKIAIOSFODNN7EXAMPLE"

func akiaGuardrail(t *testing.T) Guardrail {
	t.Helper()
	g, err := CompileGuardrail(GuardrailPolicy{Rules: []GuardrailRule{
		{Name: "aws-access-key-id", Pattern: `AKIA[0-9A-Z]{16}`},
	}})
	if err != nil {
		t.Fatalf("CompileGuardrail: %v", err)
	}
	return g
}

// RequestFromHTTP's doc says a request it "could not screen" is an error, so the
// proxy "fails closed". It does the opposite: the payload struct maps only
// `model`, `messages[].content` and `tools`, and messageText returns "" for any
// content shape it does not recognise. Screen("") matches no rule and is allowed,
// so a secret placed anywhere the struct does not reach is forwarded upstream
// having been screened as empty text.
//
// Case (a) is the sharpest: in an agent loop, tool OUTPUT is where exfiltrated
// data actually lives, and Anthropic carries it under `content`, not `text`.
func TestBodyShapesMustNotEvadeScreening(t *testing.T) {
	g := akiaGuardrail(t)

	cases := []struct {
		name string
		body string
	}{
		{
			name: "(a) anthropic tool_result carries payload under content",
			body: `{"model":"claude-x","messages":[{"role":"user","content":[
			         {"type":"tool_result","tool_use_id":"t1","content":"` + secret + `"}]}]}`,
		},
		{
			name: "(b) tool_use arguments",
			body: `{"model":"claude-x","messages":[{"role":"assistant","content":[
			         {"type":"tool_use","name":"search","input":{"query":"` + secret + `"}}]}]}`,
		},
		{
			name: "(c) top-level system prompt",
			body: `{"model":"claude-x","system":"` + secret + `","messages":[
			         {"role":"user","content":"hello"}]}`,
		},
		{
			name: "(d) OpenAI Responses API input, no messages",
			body: `{"model":"gpt-x","input":"` + secret + `"}`,
		},
		{
			name: "(e) unknown future block type",
			body: `{"model":"claude-x","messages":[{"role":"user","content":[
			         {"type":"some_future_block","payload":"` + secret + `"}]}]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, "http://upstream/v1/messages", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set(HeaderAgent, "release-reviewer")

			req, err := RequestFromHTTP(r)
			if err != nil {
				// Failing closed on a shape it cannot screen is an acceptable outcome.
				return
			}

			if d := g.Screen(req.Input); d.Allowed {
				t.Errorf("secret placed in this position was screened as %q and ALLOWED; "+
					"the guardrail never saw it", req.Input)
			}
		})
	}
}

// A malformed body must never be forwarded.
func TestMalformedBodyMustFailClosed(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "http://upstream/v1/messages", strings.NewReader(`{"model":`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(HeaderAgent, "release-reviewer")

	if _, err := RequestFromHTTP(r); err == nil {
		t.Error("malformed JSON body was accepted; it must fail closed")
	}
}
