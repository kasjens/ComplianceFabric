// Package release turns a release's generated supply-chain artifacts into control
// evidence and gates the release on it. It binds the generation harness (syft
// SBOM, SLSA provenance, evaluation runs) into the release pipeline: a declarative
// manifest names each artifact file and the producer that judges it, and the gate
// runs every producer once, appends the evidence to a fresh per-release ledger,
// and clears the release only when every record is satisfied.
//
// The producers are the same shared registry the CLI and the continuous collector
// use (internal/collect), so a release-time judgment and an after-the-fact one are
// identical. Unlike continuous collection there is no dedup (a release ledger
// starts empty) and no resilience to a broken source: a release reads files that
// were just generated, so an unreadable artifact or a failed producer is a blocked
// release, not a degraded one.
package release

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kasjens/ComplianceFabric/internal/collect"
	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/policies"
	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// Source is one evidence input for a release: a producer Type (a key in
// collect.Producers), the File holding that producer's primary input (the SBOM,
// the provenance attestation, the evaluation run), the Control its evidence keys
// to, and the aux references that producer needs. It mirrors the continuous
// collector's source spec, but reads its input from a generated file rather than a
// fetch command.
type Source struct {
	Type            string `json:"type"`
	File            string `json:"file"`
	Control         string `json:"control"`
	PoliciesDir     string `json:"policies-dir"`
	RegistryDir     string `json:"registry-dir"`
	GateFile        string `json:"gate-file"`
	SBOMPolicyFile  string `json:"sbom-policy-file"`
	ExpectedBuilder string `json:"expected-builder"`
}

// Manifest is a release's declared evidence set: the artifacts generated for this
// release and the producers that turn them into control evidence. It carries no
// schedule - a release gate runs once, at release time.
type Manifest struct {
	Release string   `json:"release"`
	Sources []Source `json:"sources"`
}

// LoadManifest reads and validates a release manifest. Validation is up front:
// the manifest must declare at least one source, and every source must name a
// known producer type and a non-empty artifact file - so a typo or a missing
// reference blocks the release loudly rather than silently producing no evidence
// (which would otherwise clear the gate by vacuity).
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, err
	}
	if len(m.Sources) == 0 {
		return Manifest{}, fmt.Errorf("manifest declares no sources")
	}
	for i, s := range m.Sources {
		if _, ok := collect.Producers[s.Type]; !ok {
			return Manifest{}, fmt.Errorf("source %d: unknown type %q", i, s.Type)
		}
		if s.File == "" {
			return Manifest{}, fmt.Errorf("source %d (%s): file is empty", i, s.Type)
		}
	}
	return m, nil
}

// Evidence reads each source's artifact file and aux references, runs its
// producer, and returns every record. A release appends all of it (the ledger is
// fresh), so unlike continuous collection there is no dedup. Any read or produce
// failure fails the whole release: missing or unreadable release evidence is a
// blocked release, not a degraded one.
func (m Manifest) Evidence() ([]evidence.Record, error) {
	var records []evidence.Record
	for i, s := range m.Sources {
		in, err := os.ReadFile(s.File)
		if err != nil {
			return nil, fmt.Errorf("source %d (%s): %w", i, s.Type, err)
		}
		params, err := resolveParams(s)
		if err != nil {
			return nil, fmt.Errorf("source %d (%s): %w", i, s.Type, err)
		}
		recs, err := collect.Run(s.Type, in, params)
		if err != nil {
			return nil, fmt.Errorf("source %d (%s): %w", i, s.Type, err)
		}
		// A declared source that yields no evidence is the same vacuity
		// LoadManifest already guards against one level up: the gate would find
		// nothing unsatisfied and clear the release. An attestation with an empty
		// subject, an Argo response with no items, or a policy report whose
		// results are all unmapped must block, not pass.
		if len(recs) == 0 {
			return nil, fmt.Errorf("source %d (%s): produced no evidence records from %s", i, s.Type, s.File)
		}
		records = append(records, recs...)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("manifest produced no evidence records")
	}
	return records, nil
}

// resolveParams turns a source's declarative references into the parsed Params its
// producer consumes, reading each referenced aux file.
func resolveParams(s Source) (collect.Params, error) {
	p := collect.Params{ControlID: s.Control, ExpectedBuilder: s.ExpectedBuilder}

	if s.PoliciesDir != "" {
		controls, err := policies.ControlsByPolicy(s.PoliciesDir)
		if err != nil {
			return collect.Params{}, fmt.Errorf("policies-dir: %w", err)
		}
		p.PolicyControls = controls
	}
	if s.RegistryDir != "" {
		reg, err := registry.Load(s.RegistryDir)
		if err != nil {
			return collect.Params{}, fmt.Errorf("registry-dir: %w", err)
		}
		p.Registry = reg
	}
	if s.GateFile != "" {
		data, err := os.ReadFile(s.GateFile)
		if err != nil {
			return collect.Params{}, fmt.Errorf("gate-file: %w", err)
		}
		if err := json.Unmarshal(data, &p.Gate); err != nil {
			return collect.Params{}, fmt.Errorf("gate-file: %w", err)
		}
	}
	if s.SBOMPolicyFile != "" {
		data, err := os.ReadFile(s.SBOMPolicyFile)
		if err != nil {
			return collect.Params{}, fmt.Errorf("sbom-policy-file: %w", err)
		}
		if err := json.Unmarshal(data, &p.SBOMPolicy); err != nil {
			return collect.Params{}, fmt.Errorf("sbom-policy-file: %w", err)
		}
	}
	return p, nil
}

// Blocking returns the records that block the release: every record that is not
// satisfied. A release clears only when this is empty, so a single banned
// component, an untrusted builder, or a failed evaluation gate blocks the ship.
func Blocking(records []evidence.Record) []evidence.Record {
	var blocking []evidence.Record
	for _, r := range records {
		if r.Result != oscal.StatusSatisfied {
			blocking = append(blocking, r)
		}
	}
	return blocking
}
