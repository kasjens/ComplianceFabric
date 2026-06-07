package collect

import "github.com/kasjens/ComplianceFabric/internal/evidence"

// Dedup keeps only the observed records that represent a change from what the
// ledger already reflects, giving the continuous collector event-log semantics:
// the ledger records state transitions, not every poll. An observation is kept
// when no prior record exists for its (control, subject) key, or when the latest
// prior result for that key differs from the observed result. Identical
// observations against the latest reflected state are dropped, so a stable
// control does not append a "still satisfied" row every interval; the posture
// rollup's "latest wins" rule still reports it correctly from the last transition.
//
// prior is the records already in the ledger, in append order (latest per key
// wins). observed is this tick's freshly produced records, processed in order so
// the running reflected state also absorbs within-tick duplicates.
func Dedup(prior, observed []evidence.Record) []evidence.Record {
	latest := make(map[string]string, len(prior))
	for _, r := range prior {
		latest[key(r)] = r.Result
	}

	var changed []evidence.Record
	for _, r := range observed {
		k := key(r)
		if prev, ok := latest[k]; ok && prev == r.Result {
			continue
		}
		latest[k] = r.Result
		changed = append(changed, r)
	}
	return changed
}

// key identifies an evidence stream by control and subject together. The unit
// separator cannot appear in a control id or subject, so it is an unambiguous
// join.
func key(r evidence.Record) string {
	return r.ControlID + "\x1f" + r.Subject
}
