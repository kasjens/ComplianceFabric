package gateway

import "testing"

func TestCompileGuardrailRejectsBadPattern(t *testing.T) {
	_, err := CompileGuardrail(GuardrailPolicy{Rules: []GuardrailRule{
		{Name: "broken", Pattern: "("},
	}})
	if err == nil {
		t.Fatal("expected an error compiling an invalid regexp pattern")
	}
}

func TestGuardrailScreen(t *testing.T) {
	g, err := CompileGuardrail(GuardrailPolicy{Rules: []GuardrailRule{
		{Name: "aws-secret-key", Pattern: `AKIA[0-9A-Z]{16}`},
		{Name: "private-key-block", Pattern: `BEGIN [A-Z ]*PRIVATE KEY`},
	}})
	if err != nil {
		t.Fatalf("CompileGuardrail: %v", err)
	}

	tests := []struct {
		name        string
		input       string
		wantAllowed bool
		wantReason  string
	}{
		{
			name:        "clean input passes",
			input:       "please summarize pull request 42",
			wantAllowed: true,
		},
		{
			name:        "input carrying a secret is blocked",
			input:       "use key AKIAIOSFODNN7EXAMPLE to fetch the bucket",
			wantAllowed: false,
			wantReason:  "content blocked by guardrail aws-secret-key",
		},
		{
			name:        "input carrying a private key is blocked",
			input:       "-----BEGIN RSA PRIVATE KEY-----",
			wantAllowed: false,
			wantReason:  "content blocked by guardrail private-key-block",
		},
		{
			name:        "empty input passes",
			input:       "",
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := g.Screen(tt.input)
			if got.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", got.Allowed, tt.wantAllowed)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}

func TestZeroGuardrailAllowsEverything(t *testing.T) {
	// A Server with no configured guardrail must not block any content.
	var g Guardrail
	if d := g.Screen("AKIAIOSFODNN7EXAMPLE"); !d.Allowed {
		t.Errorf("zero-value guardrail blocked content: %+v", d)
	}
}
