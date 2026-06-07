package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/policies"
	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// Config is the resolved continuous-collection configuration: how often to poll
// (Interval) and the sources to poll, each with its producer Params already
// resolved from the declarative config.
type Config struct {
	Interval time.Duration
	Sources  []Source
}

// sourceSpec is the on-disk shape of one source. The aux references (paths and
// strings) are resolved into the producer Params at load time, so a bad path or
// unknown type fails at startup rather than on a live tick.
type sourceSpec struct {
	Type            string   `json:"type"`
	Command         []string `json:"command"`
	Control         string   `json:"control"`
	PoliciesDir     string   `json:"policies-dir"`
	RegistryDir     string   `json:"registry-dir"`
	GateFile        string   `json:"gate-file"`
	SBOMPolicyFile  string   `json:"sbom-policy-file"`
	ExpectedBuilder string   `json:"expected-builder"`
}

type configSpec struct {
	Interval string       `json:"interval"`
	Sources  []sourceSpec `json:"sources"`
}

// LoadConfig reads, validates, and resolves a collection config file. Validation
// is total and up front: the interval must parse, every source must name a known
// producer type and a non-empty fetch command, and every referenced aux file must
// load - so the collector never starts with a config that would fail mid-run.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var spec configSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return Config{}, err
	}

	interval, err := time.ParseDuration(spec.Interval)
	if err != nil {
		return Config{}, fmt.Errorf("interval %q: %w", spec.Interval, err)
	}

	cfg := Config{Interval: interval}
	for i, s := range spec.Sources {
		if _, ok := Producers[s.Type]; !ok {
			return Config{}, fmt.Errorf("source %d: unknown type %q", i, s.Type)
		}
		if len(s.Command) == 0 {
			return Config{}, fmt.Errorf("source %d (%s): command is empty", i, s.Type)
		}
		params, err := resolveParams(s)
		if err != nil {
			return Config{}, fmt.Errorf("source %d (%s): %w", i, s.Type, err)
		}
		cfg.Sources = append(cfg.Sources, Source{Type: s.Type, Command: s.Command, Params: params})
	}
	return cfg, nil
}

// resolveParams turns a source's declarative references into the parsed Params its
// producer consumes, reading each referenced aux file.
func resolveParams(s sourceSpec) (Params, error) {
	p := Params{ControlID: s.Control, ExpectedBuilder: s.ExpectedBuilder}

	if s.PoliciesDir != "" {
		controls, err := policies.ControlsByPolicy(s.PoliciesDir)
		if err != nil {
			return Params{}, fmt.Errorf("policies-dir: %w", err)
		}
		p.PolicyControls = controls
	}
	if s.RegistryDir != "" {
		reg, err := registry.Load(s.RegistryDir)
		if err != nil {
			return Params{}, fmt.Errorf("registry-dir: %w", err)
		}
		p.Registry = reg
	}
	if s.GateFile != "" {
		data, err := os.ReadFile(s.GateFile)
		if err != nil {
			return Params{}, fmt.Errorf("gate-file: %w", err)
		}
		if err := json.Unmarshal(data, &p.Gate); err != nil {
			return Params{}, fmt.Errorf("gate-file: %w", err)
		}
	}
	if s.SBOMPolicyFile != "" {
		data, err := os.ReadFile(s.SBOMPolicyFile)
		if err != nil {
			return Params{}, fmt.Errorf("sbom-policy-file: %w", err)
		}
		if err := json.Unmarshal(data, &p.SBOMPolicy); err != nil {
			return Params{}, fmt.Errorf("sbom-policy-file: %w", err)
		}
	}
	return p, nil
}
