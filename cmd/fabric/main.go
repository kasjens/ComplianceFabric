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
	"github.com/kasjens/ComplianceFabric/internal/ledger"
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
	"       fabric evidence <pr-json-file> [control-id] [--ledger <path>]\n" +
	"       fabric ledger <verify|assess> <ledger-path>"

// run executes the CLI and returns the process exit code:
//
//	0 - command succeeded (no findings; no coverage gaps under --strict)
//	1 - validation found findings, or --strict assess found coverage gaps
//	2 - usage or load error
func run(args []string, out io.Writer) int {
	commands := map[string]bool{"validate": true, "report": true, "assess": true, "policies": true, "generate": true, "evidence": true, "ledger": true}
	if len(args) < 1 || !commands[args[0]] {
		fmt.Fprintln(out, usage)
		return 2
	}
	cmd := args[0]

	strict := false
	ledgerPath := ""
	var positional []string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case cmd == "assess" && a == "--strict":
			strict = true
		case cmd == "evidence" && a == "--ledger":
			if i+1 >= len(rest) {
				fmt.Fprintln(out, usage)
				return 2
			}
			i++
			ledgerPath = rest[i]
		default:
			positional = append(positional, a)
		}
	}

	// evidence operates on a pull-request JSON file, not a controls directory,
	// and takes an optional control id to key the emitted evidence record to and
	// an optional ledger path to append that record to.
	if cmd == "evidence" {
		if len(positional) < 1 || len(positional) > 2 {
			fmt.Fprintln(out, usage)
			return 2
		}
		controlID := ""
		if len(positional) == 2 {
			controlID = positional[1]
		}
		if ledgerPath != "" && controlID == "" {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runEvidence(positional[0], controlID, ledgerPath, out)
	}

	// ledger verify checks a ledger's hash chain is intact; ledger assess
	// normalizes its records into an OSCAL assessment-results document.
	if cmd == "ledger" {
		if len(positional) != 2 {
			fmt.Fprintln(out, usage)
			return 2
		}
		switch positional[0] {
		case "verify":
			return runLedgerVerify(positional[1], out)
		case "assess":
			return runLedgerAssess(positional[1], out)
		default:
			fmt.Fprintln(out, usage)
			return 2
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

func runEvidence(prFile, controlID, ledgerPath string, out io.Writer) int {
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

	// With a control id, emit a machine-readable evidence-ledger record and exit
	// non-zero when it is not a valid authorized change, so CI can gate on it.
	if controlID != "" {
		record := rec.AsEvidence(controlID)
		// A flagged change is still recorded: the ledger is the audit trail of
		// what was observed, satisfied or not. The exit code reflects findings.
		if ledgerPath != "" {
			if _, err := ledger.Open(ledgerPath).Append(record); err != nil {
				fmt.Fprintf(out, "error: %v\n", err)
				return 2
			}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(record); err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 2
		}
		if len(rec.Issues()) > 0 {
			return 1
		}
		return 0
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

func runLedgerVerify(path string, out io.Writer) int {
	if err := ledger.Open(path).Verify(); err != nil {
		fmt.Fprintf(out, "ledger verification failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(out, "ledger verification passed: chain intact")
	return 0
}

func runLedgerAssess(path string, out io.Writer) int {
	entries, err := ledger.Open(path).Entries()
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records := make([]evidence.Record, 0, len(entries))
	for _, e := range entries {
		records = append(records, e.Record)
	}
	results := evidence.AssessmentResults(records)
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	if len(assess.NotSatisfied(results)) > 0 {
		return 1
	}
	return 0
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
