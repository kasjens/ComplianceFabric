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
	"github.com/kasjens/ComplianceFabric/internal/report"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

// run executes the CLI and returns the process exit code:
//
//	0 - command succeeded (validation found no findings)
//	1 - validation produced findings
//	2 - usage or load error
func run(args []string, out io.Writer) int {
	commands := map[string]bool{"validate": true, "report": true, "assess": true}
	if len(args) != 2 || !commands[args[0]] {
		fmt.Fprintln(out, "usage: fabric <validate|report|assess> <controls-dir>")
		return 2
	}

	bundle, err := loader.Load(args[1])
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}

	switch args[0] {
	case "validate":
		return runValidate(bundle, out)
	case "report":
		fmt.Fprint(out, report.Render(report.Coverage(bundle)))
		return 0
	case "assess":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(assess.Assess(bundle)); err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 2
		}
		return 0
	}
	return 2
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
