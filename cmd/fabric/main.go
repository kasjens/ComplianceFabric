// Command fabric is the CLI for the Compliance Fabric. It validates and reports
// on a controls/ directory of OSCAL documents, assesses control coverage,
// verifies and composes the Kyverno policy library, and derives change-control
// evidence from GitOps pull-request records.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/assess"
	"github.com/kasjens/ComplianceFabric/internal/collect"
	"github.com/kasjens/ComplianceFabric/internal/crosswalk"
	"github.com/kasjens/ComplianceFabric/internal/dashboard"
	"github.com/kasjens/ComplianceFabric/internal/eval"
	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/gateway"
	"github.com/kasjens/ComplianceFabric/internal/generate"
	"github.com/kasjens/ComplianceFabric/internal/ledger"
	"github.com/kasjens/ComplianceFabric/internal/loader"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/policies"
	"github.com/kasjens/ComplianceFabric/internal/posture"
	"github.com/kasjens/ComplianceFabric/internal/registry"
	"github.com/kasjens/ComplianceFabric/internal/release"
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
	"       fabric policy-report <report-json-file> <policies-dir> [--ledger <path>]\n" +
	"       fabric drift <argo-apps-json-file> <control-id> [--ledger <path>]\n" +
	"       fabric trace <traces-json-file> <registry-dir> <control-id> [--ledger <path>]\n" +
	"       fabric eval-gate <eval-run-file> <gate-file> <control-id> [--ledger <path>]\n" +
	"       fabric provenance <provenance-json-file> <expected-builder-id> <control-id> [--ledger <path>]\n" +
	"       fabric sbom <sbom-json-file> <policy-file> <control-id> [--ledger <path>]\n" +
	"       fabric ledger <verify|assess|posture> <ledger-path>\n" +
	"       fabric registry validate <registry-dir>\n" +
	"       fabric gateway <registry-dir> [--addr <addr>] [--log <path>] [--guardrail <policy-file>] [--limits <limits-file>]\n" +
	"       fabric collect <config-file> --ledger <path> [--once]\n" +
	"       fabric release-gate <manifest-file> [--ledger <path>]\n" +
	"       fabric crosswalk <crosswalk-file> <source-ledger> [--ledger <path>]\n" +
	"       fabric serve <ledger-path> [--addr <addr>]"

// run executes the CLI and returns the process exit code:
//
//	0 - command succeeded (no findings; no coverage gaps under --strict)
//	1 - validation found findings, or --strict assess found coverage gaps
//	2 - usage or load error
func run(args []string, out io.Writer) int {
	commands := map[string]bool{"validate": true, "report": true, "assess": true, "policies": true, "generate": true, "evidence": true, "policy-report": true, "drift": true, "trace": true, "eval-gate": true, "provenance": true, "sbom": true, "ledger": true, "registry": true, "gateway": true, "collect": true, "release-gate": true, "crosswalk": true, "serve": true}
	if len(args) < 1 || !commands[args[0]] {
		fmt.Fprintln(out, usage)
		return 2
	}
	cmd := args[0]

	strict := false
	once := false
	ledgerPath := ""
	addr := ""
	logPath := ""
	guardrailPath := ""
	limitsPath := ""
	var positional []string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case cmd == "assess" && a == "--strict":
			strict = true
		case cmd == "collect" && a == "--once":
			once = true
		case (cmd == "evidence" || cmd == "policy-report" || cmd == "drift" || cmd == "trace" || cmd == "eval-gate" || cmd == "provenance" || cmd == "sbom" || cmd == "collect" || cmd == "release-gate" || cmd == "crosswalk") && a == "--ledger":
			if i+1 >= len(rest) {
				fmt.Fprintln(out, usage)
				return 2
			}
			i++
			ledgerPath = rest[i]
		case (cmd == "gateway" || cmd == "serve") && a == "--addr":
			if i+1 >= len(rest) {
				fmt.Fprintln(out, usage)
				return 2
			}
			i++
			addr = rest[i]
		case cmd == "gateway" && a == "--log":
			if i+1 >= len(rest) {
				fmt.Fprintln(out, usage)
				return 2
			}
			i++
			logPath = rest[i]
		case cmd == "gateway" && a == "--guardrail":
			if i+1 >= len(rest) {
				fmt.Fprintln(out, usage)
				return 2
			}
			i++
			guardrailPath = rest[i]
		case cmd == "gateway" && a == "--limits":
			if i+1 >= len(rest) {
				fmt.Fprintln(out, usage)
				return 2
			}
			i++
			limitsPath = rest[i]
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
		case "posture":
			return runLedgerPosture(positional[1], out)
		default:
			fmt.Fprintln(out, usage)
			return 2
		}
	}

	// trace turns a gateway interaction log into evidence keyed to the given
	// control, judging each interaction against the agent registry's qualified
	// surface (the agent's declared prompts and tools).
	if cmd == "trace" {
		if len(positional) != 3 {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runTrace(positional[0], positional[1], positional[2], ledgerPath, out)
	}

	// eval-gate runs an agent version's evaluation results through the promotion
	// gate and records the verdict as evidence keyed to the given control.
	if cmd == "eval-gate" {
		if len(positional) != 3 {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runEvalGate(positional[0], positional[1], positional[2], ledgerPath, out)
	}

	// provenance turns a SLSA build-provenance attestation into evidence keyed to
	// the given control, satisfied only when the artifact was built by the
	// expected trusted builder.
	if cmd == "provenance" {
		if len(positional) != 3 {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runProvenance(positional[0], positional[1], positional[2], ledgerPath, out)
	}

	// gateway runs the inline runtime admission point: it serves the same
	// qualified-surface decision that trace evaluates after the fact, but at
	// request time, and appends every handled interaction to a log the trace
	// producer can consume.
	if cmd == "gateway" {
		if len(positional) != 1 {
			fmt.Fprintln(out, usage)
			return 2
		}
		if addr == "" {
			addr = ":8080"
		}
		return runGateway(positional[0], addr, logPath, guardrailPath, limitsPath, out)
	}

	// collect runs the continuous collector: it polls every configured source,
	// produces evidence, and appends only the state changes to the ledger. --once
	// runs a single tick (so it is testable and CI-driveable); without it the
	// collector loops on the config's interval until the process is stopped.
	if cmd == "collect" {
		if len(positional) != 1 || ledgerPath == "" {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runCollect(positional[0], ledgerPath, once, out)
	}

	// release-gate runs the release evidence gate: it reads a release manifest of
	// generated supply-chain artifacts, turns each into control evidence, appends it
	// to a fresh per-release ledger, and clears the release (exit 0) only when the
	// chain verifies and every record is satisfied. This binds the generation
	// harness into the release pipeline rather than leaving it as an e2e proof.
	if cmd == "release-gate" {
		if len(positional) != 1 {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runReleaseGate(positional[0], ledgerPath, out)
	}

	// crosswalk reuses one framework's enforced controls to answer another's: it
	// reads a source ledger of existing evidence, applies a crosswalk that maps
	// target-sector citations onto the controls that already answer them, and
	// emits one derived record per mapping. This is Phase 5 cross-sector reuse —
	// the same enforced control answers DORA or NIS2 with no new enforcement.
	if cmd == "crosswalk" {
		if len(positional) != 2 {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runCrosswalk(positional[0], positional[1], ledgerPath, out)
	}

	// serve runs the live posture dashboard: a read-only HTTP surface over the
	// ledger's control-posture rollup that re-reads the ledger on every request,
	// so it reflects what the collector is appending in real time.
	if cmd == "serve" {
		if len(positional) != 1 {
			fmt.Fprintln(out, usage)
			return 2
		}
		if addr == "" {
			addr = ":8081"
		}
		return runServe(positional[0], addr, out)
	}

	// sbom turns a CycloneDX SBOM into evidence keyed to the given control,
	// judging the image's component inventory against a banned-components policy.
	if cmd == "sbom" {
		if len(positional) != 3 {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runSBOM(positional[0], positional[1], positional[2], ledgerPath, out)
	}

	// registry validate checks an agent/prompt/tool registry directory for
	// internal consistency (versions, owners, references, duplicate ids).
	if cmd == "registry" {
		if len(positional) != 2 || positional[0] != "validate" {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runRegistryValidate(positional[1], out)
	}

	// policy-report turns a Kyverno PolicyReport into evidence records keyed to
	// the controls the reported policies enforce, mapped via the policy library.
	if cmd == "policy-report" {
		if len(positional) != 2 {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runPolicyReport(positional[0], positional[1], ledgerPath, out)
	}

	// drift turns Argo CD application sync status into drift evidence records
	// keyed to the given control.
	if cmd == "drift" {
		if len(positional) != 2 {
			fmt.Fprintln(out, usage)
			return 2
		}
		return runDrift(positional[0], positional[1], ledgerPath, out)
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

func runPolicyReport(reportFile, policiesDir, ledgerPath string, out io.Writer) int {
	data, err := os.ReadFile(reportFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	policyControls, err := policies.ControlsByPolicy(policiesDir)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records, err := collect.Run("policy-report", data, collect.Params{PolicyControls: policyControls})
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return emitRecords(records, ledgerPath, out)
}

func runDrift(appsFile, controlID, ledgerPath string, out io.Writer) int {
	data, err := os.ReadFile(appsFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records, err := collect.Run("drift", data, collect.Params{ControlID: controlID})
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return emitRecords(records, ledgerPath, out)
}

// emitRecords optionally appends the records to a ledger, prints them as a JSON
// array, and returns exit 1 if any record is not satisfied so CI can gate on it.
func emitRecords(records []evidence.Record, ledgerPath string, out io.Writer) int {
	if ledgerPath != "" {
		l := ledger.Open(ledgerPath)
		for _, rec := range records {
			if _, err := l.Append(rec); err != nil {
				fmt.Fprintf(out, "error: %v\n", err)
				return 2
			}
		}
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(records); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}

	for _, rec := range records {
		if rec.Result != oscal.StatusSatisfied {
			return 1
		}
	}
	return 0
}

func runLedgerVerify(path string, out io.Writer) int {
	if err := ledger.Open(path).Verify(); err != nil {
		fmt.Fprintf(out, "ledger verification failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(out, "ledger verification passed: chain intact")
	return 0
}

// ledgerRecords reads a ledger and returns the evidence records it stores.
func ledgerRecords(path string) ([]evidence.Record, error) {
	entries, err := ledger.Open(path).Entries()
	if err != nil {
		return nil, err
	}
	records := make([]evidence.Record, 0, len(entries))
	for _, e := range entries {
		records = append(records, e.Record)
	}
	return records, nil
}

func runLedgerAssess(path string, out io.Writer) int {
	records, err := ledgerRecords(path)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
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

func runLedgerPosture(path string, out io.Writer) int {
	records, err := ledgerRecords(path)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	p := posture.Summarize(records)
	fmt.Fprint(out, p.Render())
	if len(p.NotSatisfied()) > 0 {
		return 1
	}
	return 0
}

func runEvalGate(runFile, gateFile, controlID, ledgerPath string, out io.Writer) int {
	runData, err := os.ReadFile(runFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	gateData, err := os.ReadFile(gateFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	var gate eval.Gate
	if err := json.Unmarshal(gateData, &gate); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records, err := collect.Run("eval-gate", runData, collect.Params{Gate: gate, ControlID: controlID})
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return emitRecords(records, ledgerPath, out)
}

func runProvenance(provenanceFile, expectedBuilder, controlID, ledgerPath string, out io.Writer) int {
	data, err := os.ReadFile(provenanceFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records, err := collect.Run("provenance", data, collect.Params{ExpectedBuilder: expectedBuilder, ControlID: controlID})
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return emitRecords(records, ledgerPath, out)
}

func runSBOM(sbomFile, policyFile, controlID, ledgerPath string, out io.Writer) int {
	sbomData, err := os.ReadFile(sbomFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	policyData, err := os.ReadFile(policyFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	var policy evidence.SBOMPolicy
	if err := json.Unmarshal(policyData, &policy); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records, err := collect.Run("sbom", sbomData, collect.Params{SBOMPolicy: policy, ControlID: controlID})
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return emitRecords(records, ledgerPath, out)
}

func runTrace(tracesFile, registryDir, controlID, ledgerPath string, out io.Writer) int {
	data, err := os.ReadFile(tracesFile)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	reg, err := registry.Load(registryDir)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records, err := collect.Run("trace", data, collect.Params{Registry: reg, ControlID: controlID})
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return emitRecords(records, ledgerPath, out)
}

// runGateway loads the agent registry, opens the optional interaction log for
// appending, and serves the inline gateway until the process is stopped. This is
// the irreducible network shell over the TDD-covered gateway.Server: the
// admission decision and the log shape it writes are exercised by unit tests, so
// this function only wires inputs to ListenAndServe.
func runGateway(registryDir, addr, logPath, guardrailPath, limitsPath string, out io.Writer) int {
	reg, err := registry.Load(registryDir)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}

	// A bad guardrail policy is caught here, before the listener binds, so the
	// gateway never starts serving with an unparseable or uncompilable policy.
	var guard gateway.Guardrail
	if guardrailPath != "" {
		policyData, err := os.ReadFile(guardrailPath)
		if err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 2
		}
		var policy gateway.GuardrailPolicy
		if err := json.Unmarshal(policyData, &policy); err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 2
		}
		guard, err = gateway.CompileGuardrail(policy)
		if err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 2
		}
	}

	// A bad limits file is caught here too, before the listener binds, so the
	// gateway never starts serving with budgets it could not fully parse.
	var limiter *gateway.Limiter
	if limitsPath != "" {
		limits, err := gateway.LoadLimits(limitsPath)
		if err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 2
		}
		limiter = gateway.NewLimiter(limits)
	}

	var logw io.Writer
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 2
		}
		defer f.Close()
		logw = f
	}

	srv := &gateway.Server{Registry: reg, Guardrail: guard, Limiter: limiter, Log: logw}
	fmt.Fprintf(out, "agent gateway listening on %s (registry %s", addr, registryDir)
	if guardrailPath != "" {
		fmt.Fprintf(out, ", guardrail %s", guardrailPath)
	}
	if limitsPath != "" {
		fmt.Fprintf(out, ", limits %s", limitsPath)
	}
	if logPath != "" {
		fmt.Fprintf(out, ", log %s", logPath)
	}
	fmt.Fprintln(out, ")")
	if err := http.ListenAndServe(addr, srv); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return 0
}

// runCollect loads a declarative collection config and drives the collector. The
// config validation (types, commands, aux files) happens in collect.LoadConfig,
// so a bad config fails here before any tick. With once it runs a single tick and
// returns; otherwise it loops on the configured interval. The collector's logic
// (fetch, produce, dedup, append) is TDD-covered; this shell only wires process
// execution (the fetch commands) and the time-driven loop, the two irreducibly
// untestable edges.
func runCollect(configPath, ledgerPath string, once bool, out io.Writer) int {
	cfg, err := collect.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}

	c := &collect.Collector{
		Sources: cfg.Sources,
		Ledger:  ledger.Open(ledgerPath),
		Fetch:   execFetch,
	}

	if once {
		changed, err := c.Tick()
		return reportTick(changed, err, out)
	}

	fmt.Fprintf(out, "collector started: %d source(s), interval %s, ledger %s\n",
		len(cfg.Sources), cfg.Interval, ledgerPath)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for range ticker.C {
		// In daemon mode a tick's outcome is reported but never aborts the loop: a
		// broken source degrades collection rather than stopping it.
		changed, err := c.Tick()
		reportTick(changed, err, out)
	}
	return 0
}

// reportTick prints a tick's recorded changes and any per-source warnings. It
// returns exit 1 when the tick reported an error (so a single --once run surfaces
// a broken source) and 0 otherwise.
func reportTick(changed []evidence.Record, err error, out io.Writer) int {
	fmt.Fprintf(out, "tick: %d change(s) recorded\n", len(changed))
	for _, r := range changed {
		fmt.Fprintf(out, "  [%s] %s %s\n", r.Result, r.ControlID, r.Subject)
	}
	if err != nil {
		fmt.Fprintf(out, "tick warnings: %v\n", err)
		return 1
	}
	return 0
}

// runReleaseGate gates a release on its generated evidence. It loads the release
// manifest, runs every producer over the named artifacts, optionally appends the
// resulting records to a fresh per-release ledger and verifies the chain, prints
// the posture rollup, and exits non-zero when the chain fails to verify or any
// control is not satisfied - so a release with a banned component, an untrusted
// builder, or a failed evaluation gate is stopped. The manifest loading and the
// gate decision are TDD-covered in internal/release; this shell only wires file
// and ledger I/O.
func runReleaseGate(manifestPath, ledgerPath string, out io.Writer) int {
	m, err := release.LoadManifest(manifestPath)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records, err := m.Evidence()
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}

	if ledgerPath != "" {
		l := ledger.Open(ledgerPath)
		for _, rec := range records {
			if _, err := l.Append(rec); err != nil {
				fmt.Fprintf(out, "error: %v\n", err)
				return 2
			}
		}
		if err := l.Verify(); err != nil {
			fmt.Fprintf(out, "release blocked: ledger verification failed: %v\n", err)
			return 1
		}
	}

	fmt.Fprint(out, posture.Summarize(records).Render())

	if blocking := release.Blocking(records); len(blocking) > 0 {
		fmt.Fprintf(out, "release blocked: %d control(s) not satisfied\n", len(blocking))
		return 1
	}
	fmt.Fprintf(out, "release cleared: %d evidence record(s), all satisfied\n", len(records))
	return 0
}

// runCrosswalk reads a source ledger of existing evidence and a crosswalk that
// maps target-sector citations onto the controls that already answer them, then
// emits one derived record per mapping. With --ledger the derived records are
// appended to a ledger so the cross-sector rollup becomes durable evidence. The
// exit code follows emitRecords: non-zero when any target citation is not
// satisfied, so a gap in the second framework surfaces in the pipeline.
func runCrosswalk(crosswalkPath, sourceLedger, ledgerPath string, out io.Writer) int {
	data, err := os.ReadFile(crosswalkPath)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	var cw crosswalk.Crosswalk
	if err := json.Unmarshal(data, &cw); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	records, err := ledgerRecords(sourceLedger)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return emitRecords(crosswalk.Apply(records, cw), ledgerPath, out)
}

// execFetch obtains a source's raw input by running its fetch command and
// capturing stdout. This is the production Fetcher injected into the collector;
// the collector's tests inject an in-memory fetcher instead.
func execFetch(command []string) ([]byte, error) {
	return exec.Command(command[0], command[1:]...).Output()
}

// runServe runs the live posture dashboard. The dashboard handler re-reads the
// ledger on every request (via ledgerRecords) so the page stays current as the
// collector appends; this shell validates the ledger is readable up front - so a
// bad path fails before the listener binds rather than on the first request - then
// serves until the process is stopped. ListenAndServe is the only untested edge;
// the rendering is covered in internal/dashboard.
func runServe(ledgerPath, addr string, out io.Writer) int {
	if _, err := ledgerRecords(ledgerPath); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}

	h := dashboard.Handler{
		Source: func() ([]evidence.Record, error) { return ledgerRecords(ledgerPath) },
	}
	fmt.Fprintf(out, "posture dashboard listening on %s (ledger %s)\n", addr, ledgerPath)
	if err := http.ListenAndServe(addr, h); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	return 0
}

func runRegistryValidate(dir string, out io.Writer) int {
	r, err := registry.Load(dir)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	findings := registry.Validate(r)
	if len(findings) == 0 {
		fmt.Fprintln(out, "registry validation passed: no findings")
		return 0
	}
	fmt.Fprintf(out, "%d finding(s):\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(out, "  [%s] %s: %s\n", f.Severity, f.Rule, f.Message)
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
