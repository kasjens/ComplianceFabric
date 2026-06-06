// Command fabric is the CLI for the GxP Compliance Fabric. Today it validates a
// controls/ directory of OSCAL documents for internal consistency.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kasjens/ComplianceFabric/internal/assess"
	"github.com/kasjens/ComplianceFabric/internal/loader"
	"github.com/kasjens/ComplianceFabric/internal/policies"
	"github.com/kasjens/ComplianceFabric/internal/report"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

const usage = "usage: fabric <validate|report> <controls-dir>\n" +
	"       fabric assess [--strict] <controls-dir>\n" +
	"       fabric policies <controls-dir> <policies-dir>"

// run executes the CLI and returns the process exit code:
//
//	0 - command succeeded (no findings; no coverage gaps under --strict)
//	1 - validation found findings, or --strict assess found coverage gaps
//	2 - usage or load error
func run(args []string, out io.Writer) int {
	commands := map[string]bool{"validate": true, "report": true, "assess": true, "policies": true}
	if len(args) < 1 || !commands[args[0]] {
		fmt.Fprintln(out, usage)
		return 2
	}
	cmd := args[0]

	strict := false
	var positional []string
	for _, a := range args[1:] {
		switch {
		case cmd == "assess" && a == "--strict":
			strict = true
		default:
			positional = append(positional, a)
		}
	}

	wantArgs := 1
	if cmd == "policies" {
		wantArgs = 2
	}
	if len(positional) != wantArgs {
		fmt.Fprintln(out, usage)
		return 2
	}

	bundle, err := loader.Load(positional[0])
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}

	switch cmd {
	case "validate":
		return runValidate(bundle, out)
	case "report":
		fmt.Fprint(out, report.Render(report.Coverage(bundle)))
		return 0
	case "assess":
		return runAssess(bundle, strict, out)
	case "policies":
		return runPolicies(bundle, positional[1], out)
	}
	return 2
}

func runPolicies(bundle validate.Bundle, policiesDir string, out io.Writer) int {
	findings := policies.Verify(bundle, policiesDir)
	if len(findings) == 0 {
		fmt.Fprintln(out, "policy verification passed: no findings")
		return 0
	}
	fmt.Fprintf(out, "%d finding(s):\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(out, "  [%s] %s: %s\n", f.Severity, f.Rule, f.Message)
	}
	return 1
}

func runAssess(bundle validate.Bundle, strict bool, out io.Writer) int {
	results := assess.Assess(bundle)
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	if strict && len(assess.NotSatisfied(results)) > 0 {
		return 1
	}
	return 0
}

func runValidate(bundle validate.Bundle, out io.Writer) int {
	findings := validate.Run(bundle)
	if len(findings) == 0 {
		fmt.Fprintln(out, "validation passed: no findings")
		return 0
	}

	fmt.Fprintf(out, "%d finding(s):\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(out, "  [%s] %s: %s\n", f.Severity, f.Rule, f.Message)
	}
	return 1
}
