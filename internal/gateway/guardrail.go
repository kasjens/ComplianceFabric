package gateway

import "regexp"

// GuardrailRule is one named content rule. A request whose input matches Pattern
// is blocked, and the rule's Name is what the denial reason and the interaction
// log record — so an auditor sees which guardrail fired, not just that one did.
type GuardrailRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// GuardrailPolicy is the authoritative set of content rules the gateway screens
// agent input against, kept as data so it lives in Git and changes through the
// same review as any other policy. It complements the registry check: the
// registry decides whether an agent may act at all, the guardrail decides whether
// the content of a specific request is allowed to pass.
type GuardrailPolicy struct {
	Rules []GuardrailRule `json:"rules"`
}

// Guardrail is a compiled GuardrailPolicy ready to screen request content. Its
// zero value screens nothing, so a gateway with no guardrail configured admits
// all content (the registry check still applies).
type Guardrail struct {
	rules []compiledRule
}

type compiledRule struct {
	name string
	re   *regexp.Regexp
}

// CompileGuardrail compiles every rule's pattern up front, returning an error for
// the first pattern that is not a valid regexp. Compiling once, at load time,
// keeps Screen allocation-free on the request path and surfaces a bad policy
// before the gateway starts serving rather than on a live request.
func CompileGuardrail(p GuardrailPolicy) (Guardrail, error) {
	rules := make([]compiledRule, 0, len(p.Rules))
	for _, r := range p.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return Guardrail{}, err
		}
		rules = append(rules, compiledRule{name: r.Name, re: re})
	}
	return Guardrail{rules: rules}, nil
}

// active reports whether the guardrail has any rules. The proxy uses it to skip
// buffering and screening an upstream response when no content policy is
// configured, so an unguarded proxy streams responses through untouched.
func (g Guardrail) active() bool {
	return len(g.rules) > 0
}

// Screen returns a deny Decision naming the first rule the input matches, or an
// allow Decision when no rule matches. The rules are checked in policy order, so
// the most specific or highest-priority rule should be listed first.
func (g Guardrail) Screen(input string) Decision {
	for _, r := range g.rules {
		if r.re.MatchString(input) {
			return Decision{Allowed: false, Reason: "content blocked by guardrail " + r.name}
		}
	}
	return Decision{Allowed: true}
}
