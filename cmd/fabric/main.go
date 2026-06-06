// Command fabric is the CLI for the Compliance Fabric. It validates and reports
// on a controls/ directory of OSCAL documents, assesses control coverage,
// verifies and composes the Kyverno policy library, and derives change-control
// evidence from GitOps pull-request records.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kasjens/ComplianceFabric/internal/assess"
	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/generate"
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
	"       fabric policies <controls-dir> <policies-dir>\n" +
	"       fabric generate <controls-dir> <policies-dir> <out-dir>\n" +
	"       fabric evidence <pr-json-file>"

// run executes the CLI and returns the process exit code:
//
//	0 - command succeeded (no findings; no coverage gaps under --strict)
//	1 - validation found findings, or --strict assess found coverage gaps
//	2 - usage or load error
func run(args []string, out io.Writer) int {
	commands := map[string]bool{"validate": true, "report": true, "assess": true, "policies": true, "generate": true, "evidence": true}
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
	switch cmd {
	case "policies":
		wantArgs = 2
	case "generate":
		wantArgs = 3
	}
	if len(positional) != wantArgs {
		fmt.Fprintln(out, usage)
		return 2
	}

	// evidence operates on a pull-request JSON file, not a controls directory.
	if cmd == "evidence" {
		return runEvidence(positional[0], out)
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
	case "generate":
		return runGenerate(bundle, positional[1], positional[2], out)
	}
	return 2
}

func runEvidence(prFile string, out io.Writer) int {
	data, err := os.ReadFile(prFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	rec, err := evidence.Extract(data)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	fmt.Fprintf(out, "PR #%d by %s\n", rec.Number, rec.Author)
	fmt.Fprintf(out, "  merge commit: %s\n", rec.MergeCommit)
	fmt.Fprintf(out, "  merged at:    %s\n", rec.MergedAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(out, "  approvers:    %v\n", rec.Approvers)

	issues := rec.Issues()
	if len(issues) == 0 {
		fmt.Fprintln(out, "valid authorized change: no findings")
		return 0
	}
	fmt.Fprintf(out, "%d finding(s):\n", len(issues))
	for _, msg := range issues {
		fmt.Fprintf(out, "  [error] change-control: %s\n", msg)
	}
	return 1
}

func runGenerate(bundle validate.Bundle, policiesDir, outDir string, out io.Writer) int {
	res, err := generate.Compose(bundle, policiesDir)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}
	if err := generate.Write(res, outDir); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	fmt.Fprintf(out, "composed %d policies for %d selected controls into %s\n",
		len(res.Policies), len(res.SelectedControls), outDir)
	return 0
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
