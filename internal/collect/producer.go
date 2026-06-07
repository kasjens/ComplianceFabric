// Package collect is the single definition of every evidence source. Each of the
// fabric evidence producers — change-control, Kyverno policy results, GitOps
// drift, agent traces, eval-gate verdicts, build provenance, and SBOM content —
// is registered here under a stable type name behind one uniform interface, so
// the on-invocation CLI commands and the continuous collector both run a source
// the same way rather than keeping a separate copy of the wiring each. Producers
// stay pure: they take the source's raw input plus the parsed auxiliary
// configuration in Params, and never read files or the clock themselves, which
// keeps them testable in memory and keeps file and network I/O at the edges.
package collect

import (
	"fmt"

	"github.com/kasjens/ComplianceFabric/internal/eval"
	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// Params carries the parsed, producer-specific configuration a producer needs
// beyond its raw input. Each producer reads only the fields relevant to it; the
// rest stay zero. Keeping these as already-parsed values (not file paths) is what
// lets producers remain pure functions.
type Params struct {
	// ControlID is the control most producers key their records to.
	ControlID string
	// ExpectedBuilder is the trusted builder identity the provenance producer
	// requires.
	ExpectedBuilder string
	// PolicyControls maps a Kyverno policy id to the control ids it enforces, as
	// the policy-report producer needs to key results to controls.
	PolicyControls map[string][]string
	// Gate is the promotion gate the eval-gate producer judges a run against.
	Gate eval.Gate
	// SBOMPolicy is the banned-components policy the sbom producer screens against.
	SBOMPolicy evidence.SBOMPolicy
	// Registry is the agent registry the trace producer judges interactions
	// against.
	Registry registry.Registry
}

// Producer turns one source's raw input into evidence records, using Params for
// its configuration. It is the uniform interface the CLI and the continuous
// collector both invoke.
type Producer func(input []byte, p Params) ([]evidence.Record, error)

// Producers is the registry of evidence sources keyed by a stable type name. The
// names are exactly the tokens the fabric subcommands use, so a source config and
// a CLI command name refer to the same producer.
var Producers = map[string]Producer{
	"change-control": func(in []byte, p Params) ([]evidence.Record, error) {
		rec, err := evidence.Extract(in)
		if err != nil {
			return nil, err
		}
		return []evidence.Record{rec.AsEvidence(p.ControlID)}, nil
	},
	"policy-report": func(in []byte, p Params) ([]evidence.Record, error) {
		return evidence.FromPolicyReport(in, p.PolicyControls)
	},
	"drift": func(in []byte, p Params) ([]evidence.Record, error) {
		return evidence.FromArgoApplications(in, p.ControlID)
	},
	"eval-gate": func(in []byte, p Params) ([]evidence.Record, error) {
		return evidence.FromEvalGate(in, p.Gate, p.ControlID)
	},
	"provenance": func(in []byte, p Params) ([]evidence.Record, error) {
		return evidence.FromProvenance(in, p.ExpectedBuilder, p.ControlID)
	},
	"sbom": func(in []byte, p Params) ([]evidence.Record, error) {
		return evidence.FromSBOM(in, p.SBOMPolicy, p.ControlID)
	},
	"trace": func(in []byte, p Params) ([]evidence.Record, error) {
		return evidence.FromAgentTraces(in, p.Registry, p.ControlID)
	},
}

// Run looks up the producer for sourceType and runs it over the input. An unknown
// type is an error, so a typo in a source config fails loudly rather than
// silently collecting nothing.
func Run(sourceType string, input []byte, p Params) ([]evidence.Record, error) {
	producer, ok := Producers[sourceType]
	if !ok {
		return nil, fmt.Errorf("unknown evidence source type %q", sourceType)
	}
	return producer(input, p)
}
