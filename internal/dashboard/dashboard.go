// Package dashboard serves the live control-posture rollup over HTTP: a read-only
// surface over posture.Summarize that re-reads its source on every request, so the
// page reflects the ledger's current state as the continuous collector appends to
// it. It is the live counterpart to the one-shot `fabric ledger posture` table.
//
// The decision-free rendering here is exercised by tests with an in-memory source;
// the production wiring (read the ledger file, ListenAndServe) is the only part
// left to the CLI edge, mirroring the gateway's split.
package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/posture"
)

// Handler renders the live control posture. Source returns the current evidence
// records; in production it reads the append-only ledger, so each request reflects
// the latest appended state. Injecting it keeps the handler free of file I/O and
// testable with in-memory records.
type Handler struct {
	Source func() ([]evidence.Record, error)
}

// jsonControl is the machine-readable shape of one control's posture. It mirrors
// the evidence Record's control-id naming so the dashboard's JSON reads
// consistently with the rest of the API.
type jsonControl struct {
	ControlID    string `json:"control-id"`
	Status       string `json:"status"`
	Records      int    `json:"records"`
	Lapses       int    `json:"lapses"`
	LastObserved string `json:"last-observed,omitempty"`
}

// jsonPosture is the /posture.json body: the per-control rows plus a summary a
// monitor can gate on without re-deriving it.
type jsonPosture struct {
	Controls []jsonControl `json:"controls"`
	Summary  struct {
		Total     int `json:"total"`
		Satisfied int `json:"satisfied"`
		Gaps      int `json:"gaps"`
	} `json:"summary"`
}

// jsonTrendPoint is one moment in the coverage timeline, machine-readable so a
// monitor can chart how coverage moved rather than only where it stands now.
type jsonTrendPoint struct {
	At        string `json:"at"`
	Total     int    `json:"total"`
	Satisfied int    `json:"satisfied"`
}

// jsonTrend is the /trend.json body: the coverage-over-time series.
type jsonTrend struct {
	Points []jsonTrendPoint `json:"points"`
}

// ServeHTTP routes the read-only surface: the root renders an HTML dashboard and
// /posture.json the same rollup as JSON. Only GET is allowed; any other path is a
// 404 and a source read failure is a 500.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/":
		h.serveHTML(w)
	case "/posture.json":
		h.serveJSON(w)
	case "/trend.json":
		h.serveTrendJSON(w)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// load reads the current records and rolls them up. It is called per request so
// the surface stays live.
func (h Handler) load() (posture.Posture, error) {
	records, err := h.Source()
	if err != nil {
		return posture.Posture{}, err
	}
	return posture.Summarize(records), nil
}

func (h Handler) serveJSON(w http.ResponseWriter) {
	p, err := h.load()
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var body jsonPosture
	for _, c := range p.Controls {
		jc := jsonControl{ControlID: c.ControlID, Status: c.Status, Records: c.Records, Lapses: c.Lapses}
		if !c.LastObserved.IsZero() {
			jc.LastObserved = c.LastObserved.Format(time.RFC3339)
		}
		body.Controls = append(body.Controls, jc)
	}
	body.Summary.Total = len(p.Controls)
	body.Summary.Gaps = len(p.NotSatisfied())
	body.Summary.Satisfied = body.Summary.Total - body.Summary.Gaps

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

// serveTrendJSON exposes the coverage-over-time series the dashboard plots, so a
// monitor can chart how coverage moved rather than only re-deriving where it
// stands now.
func (h Handler) serveTrendJSON(w http.ResponseWriter) {
	records, err := h.Source()
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var body jsonTrend
	for _, p := range posture.TrendOf(records).Points {
		body.Points = append(body.Points, jsonTrendPoint{
			At:        p.At.Format(time.RFC3339),
			Total:     p.Total,
			Satisfied: p.Satisfied,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func (h Handler) serveHTML(w http.ResponseWriter) {
	records, err := h.Source()
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p := posture.Summarize(records)

	gaps := len(p.NotSatisfied())
	view := pageView{
		Total:     len(p.Controls),
		Gaps:      gaps,
		Satisfied: len(p.Controls) - gaps,
		Trend:     buildTrend(posture.TrendOf(records)),
	}
	for _, c := range p.Controls {
		last := "-"
		if !c.LastObserved.IsZero() {
			last = c.LastObserved.Format(time.RFC3339)
		}
		view.Rows = append(view.Rows, rowView{
			ControlID:    c.ControlID,
			Status:       c.Status,
			Satisfied:    c.Status == oscal.StatusSatisfied,
			Records:      c.Records,
			Lapses:       c.Lapses,
			LastObserved: last,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The template is parsed from a trusted constant and all dynamic values are
	// auto-escaped by html/template, so control ids cannot inject markup.
	_ = pageTmpl.Execute(w, view)
}

type pageView struct {
	Total     int
	Satisfied int
	Gaps      int
	Rows      []rowView
	Trend     *trendView
}

// trendView is the rendered coverage sparkline: a polyline points string mapped
// into a fixed viewBox, plus the labels framing it. It is nil when there is no
// history to plot, so the template can omit the section entirely.
type trendView struct {
	Width      int
	Height     int
	Polyline   string // "x,y x,y ..." in viewBox coordinates
	FirstLabel string
	LastLabel  string
	Latest     string // "satisfied/total" at the most recent point
}

// buildTrend projects the coverage timeline onto a fixed-size sparkline. The
// y-axis is the satisfied-control count scaled against the peak total ever seen,
// so the line reads as "share of known controls satisfied" over time. A single
// point still plots (as a flat two-vertex line) so the section is meaningful as
// soon as any evidence exists.
func buildTrend(tr posture.Trend) *trendView {
	pts := tr.Points
	if len(pts) == 0 {
		return nil
	}

	const w, h = 240, 48
	const pad = 4

	maxTotal := 0
	for _, p := range pts {
		if p.Total > maxTotal {
			maxTotal = p.Total
		}
	}
	if maxTotal == 0 {
		maxTotal = 1
	}

	// y maps a satisfied count to a viewBox row (0 at top), with padding so the
	// extremes are not clipped against the frame.
	y := func(satisfied int) float64 {
		frac := float64(satisfied) / float64(maxTotal)
		return float64(h-pad) - frac*float64(h-2*pad)
	}

	var b strings.Builder
	for i, p := range pts {
		var x float64
		if len(pts) == 1 {
			x = float64(w) / 2
		} else {
			x = float64(pad) + float64(i)/float64(len(pts)-1)*float64(w-2*pad)
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y(p.Satisfied))
	}
	poly := b.String()
	// A lone point needs a second vertex or the polyline renders nothing.
	if len(pts) == 1 {
		poly = poly + " " + poly
	}

	last := pts[len(pts)-1]
	return &trendView{
		Width:      w,
		Height:     h,
		Polyline:   poly,
		FirstLabel: pts[0].At.Format("2006-01-02"),
		LastLabel:  last.At.Format("2006-01-02"),
		Latest:     fmt.Sprintf("%d/%d", last.Satisfied, last.Total),
	}
}

type rowView struct {
	ControlID    string
	Status       string
	Satisfied    bool
	Records      int
	Lapses       int
	LastObserved string
}

var pageTmpl = template.Must(template.New("posture").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compliance Fabric &mdash; control posture</title>
<style>
 body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
 h1 { font-size: 1.25rem; }
 .summary { margin: 1rem 0; font-size: 1rem; }
 .summary .gaps { color: #b00020; font-weight: 600; }
 .summary.clean .gaps { color: #1a7f37; }
 table { border-collapse: collapse; width: 100%; }
 th, td { text-align: left; padding: 0.4rem 0.75rem; border-bottom: 1px solid #ddd; }
 th { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: #555; }
 .status { font-weight: 600; }
 .satisfied .status { color: #1a7f37; }
 .gap .status { color: #b00020; }
 .trend { margin: 1rem 0 1.5rem; }
 .trend h2 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: #555; margin: 0 0 0.4rem; }
 .trend svg { display: block; }
 .trend .axis { display: flex; justify-content: space-between; width: 240px; color: #888; font-size: 0.75rem; margin-top: 0.2rem; }
 footer { margin-top: 1.5rem; color: #888; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>Control posture</h1>
<p class="summary{{if eq .Gaps 0}} clean{{end}}">
 {{.Total}} controls &middot; {{.Satisfied}} currently satisfied &middot;
 <span class="gaps">{{.Gaps}} with open gaps</span>
</p>
{{with .Trend}}
<section class="trend">
 <h2>Coverage trend</h2>
 <svg width="{{.Width}}" height="{{.Height}}" viewBox="0 0 {{.Width}} {{.Height}}" role="img" aria-label="Satisfied controls over time, currently {{.Latest}}">
  <polyline fill="none" stroke="#1a7f37" stroke-width="2" points="{{.Polyline}}" />
 </svg>
 <div class="axis"><span>{{.FirstLabel}}</span><span>{{.Latest}} satisfied</span><span>{{.LastLabel}}</span></div>
</section>
{{end}}
<table>
<thead><tr><th>Control</th><th>Status</th><th>Records</th><th>Lapses</th><th>Last observed</th></tr></thead>
<tbody>
{{range .Rows}}
 <tr class="{{if .Satisfied}}satisfied{{else}}gap{{end}}">
  <td>{{.ControlID}}</td>
  <td class="status">{{.Status}}</td>
  <td>{{.Records}}</td>
  <td>{{.Lapses}}</td>
  <td>{{.LastObserved}}</td>
 </tr>
{{else}}
 <tr><td colspan="5">No evidence recorded yet.</td></tr>
{{end}}
</tbody>
</table>
<footer>Live view of the evidence ledger &middot; refresh to update.</footer>
</body>
</html>
`))
