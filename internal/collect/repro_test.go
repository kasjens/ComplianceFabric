package collect

import (
	"testing"
)

// REPRODUCTION — Workstream R.2, plan item 5.3. Expected to FAIL against cac9f78.

// LoadConfig validates only that the interval PARSES as a duration.
// time.ParseDuration happily accepts "0s" and "-30s", and time.NewTicker panics
// on a non-positive duration. Because `collect --once` bypasses the ticker
// entirely, this only ever manifests in the long-running production path.
func TestRepro53NonPositiveIntervalMustBeRejected(t *testing.T) {
	cases := []string{"0s", "-30s", "0h"}

	for _, interval := range cases {
		t.Run(interval, func(t *testing.T) {
			dir := t.TempDir()
			apps := writeFile(t, dir, "apps.json", `{"items":[]}`)
			_ = apps

			cfg := writeFile(t, dir, "collect.json", `{
				"interval": "`+interval+`",
				"sources": [
					{"type":"drift","command":["true"],"control":"annex11-11-periodic-evaluation"}
				]
			}`)

			if _, err := LoadConfig(cfg); err == nil {
				t.Errorf("LoadConfig accepted interval %q; NewTicker panics on a "+
					"non-positive duration, taking down the collector in production", interval)
			}
		})
	}
}
