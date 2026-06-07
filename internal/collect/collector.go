package collect

import (
	"errors"
	"fmt"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/ledger"
)

// Fetcher obtains a source's raw input by running its fetch command (for example
// `kubectl get policyreport -o json`). It is injected so the collector's
// orchestration is testable without spawning real processes; the production
// fetcher shells out via os/exec at the CLI edge.
type Fetcher func(command []string) ([]byte, error)

// Source is one configured evidence stream the collector polls: a producer type
// (a key in Producers), the command that fetches its input, and the resolved
// parameters that producer needs.
type Source struct {
	Type    string
	Command []string
	Params  Params
}

// Collector polls a set of sources and appends only the state changes to an
// append-only ledger. It holds no schedule itself: each call to Tick polls every
// source once. The CLI drives Tick on an interval (or once), which keeps the only
// time-dependent part - the loop - out of the tested core.
type Collector struct {
	Sources []Source
	Ledger  *ledger.Ledger
	Fetch   Fetcher
}

// Tick polls every source once: it fetches each source's input, produces evidence
// records, keeps only those that changed versus what the ledger already reflects
// (Dedup), and appends the changes. It returns the appended records. A source
// that fails to fetch or produce does not abort the others; its failure is
// collected and returned as a joined error, so a single broken source degrades
// rather than stops continuous collection.
func (c *Collector) Tick() ([]evidence.Record, error) {
	entries, err := c.Ledger.Entries()
	if err != nil {
		return nil, err
	}
	prior := make([]evidence.Record, 0, len(entries))
	for _, e := range entries {
		prior = append(prior, e.Record)
	}

	var observed []evidence.Record
	var errs []error
	for _, s := range c.Sources {
		in, err := c.Fetch(s.Command)
		if err != nil {
			errs = append(errs, fmt.Errorf("source %s: fetch: %w", s.Type, err))
			continue
		}
		recs, err := Run(s.Type, in, s.Params)
		if err != nil {
			errs = append(errs, fmt.Errorf("source %s: produce: %w", s.Type, err))
			continue
		}
		observed = append(observed, recs...)
	}

	changed := Dedup(prior, observed)
	for _, r := range changed {
		if _, err := c.Ledger.Append(r); err != nil {
			errs = append(errs, fmt.Errorf("append: %w", err))
			return changed, errors.Join(errs...)
		}
	}
	return changed, errors.Join(errs...)
}
