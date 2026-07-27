package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// The proxy reads an agent's declared identity from these request headers — the
// part of the gateway decision that is not in the model API's own body. The model
// and the tools come from the body the caller is already sending; the agent and
// the prompt it is running are asserted alongside, the way a caller authenticates
// and declares intent at the wire. Cost is an optional caller-asserted charge for
// the rate/cost limiter.
const (
	HeaderAgent  = "X-Fabric-Agent"
	HeaderPrompt = "X-Fabric-Prompt"
	HeaderCost   = "X-Fabric-Cost"
)

// RequestFromHTTP recovers a gateway Request from a live upstream LLM/MCP request:
// the agent and prompt from headers, and the model, tool names, and message text
// from the JSON body. Both the OpenAI tool shape (tools[].function.name) and the
// Anthropic shape (tools[].name) are read, and message content is taken as the
// input the guardrail screens. The body is left readable so the proxy can still
// forward the original payload upstream unchanged. A request with no agent
// identity, an unparseable cost, or a malformed body is an error, so the proxy
// fails closed rather than forwarding an interaction it could not screen.
func RequestFromHTTP(r *http.Request) (Request, error) {
	agent := r.Header.Get(HeaderAgent)
	if agent == "" {
		return Request{}, fmt.Errorf("missing %s header", HeaderAgent)
	}
	req := Request{Agent: agent, Prompt: r.Header.Get(HeaderPrompt)}

	if c := r.Header.Get(HeaderCost); c != "" {
		cost, err := strconv.ParseFloat(c, 64)
		if err != nil {
			return Request{}, fmt.Errorf("invalid %s header: %w", HeaderCost, err)
		}
		// ParseFloat accepts "NaN", "Inf" and negatives. A NaN cost makes every
		// budget comparison false (so it is allowed AND poisons the window's
		// running total), and a negative cost refunds budget outright. Either
		// way the caller would control its own limit.
		if math.IsNaN(cost) || math.IsInf(cost, 0) || cost < 0 {
			return Request{}, fmt.Errorf("invalid %s header: cost must be a finite, non-negative number", HeaderCost)
		}
		req.Cost = cost
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return Request{}, err
	}
	// Leave the consumed body readable for the reverse proxy to forward verbatim.
	r.Body = io.NopCloser(bytes.NewReader(body))

	if len(bytes.TrimSpace(body)) == 0 {
		return req, nil
	}

	var payload struct {
		Model    string `json:"model"`
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Tools []struct {
			Name     string `json:"name"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return Request{}, fmt.Errorf("malformed request body: %w", err)
	}
	req.Model = payload.Model
	for _, t := range payload.Tools {
		name := t.Function.Name
		if name == "" {
			name = t.Name
		}
		if name != "" {
			req.Tools = append(req.Tools, name)
		}
	}
	var inputs []string
	for _, m := range payload.Messages {
		if s := messageText(m.Content); s != "" {
			inputs = append(inputs, s)
		}
	}
	req.Input = strings.Join(inputs, "\n")
	return req, nil
}

// messageText flattens a chat message's content to plain text for screening. The
// content is either a plain string (OpenAI) or an array of typed blocks with a
// text field (Anthropic); both are reduced to their text so the guardrail screens
// what the agent actually sends regardless of API shape.
func messageText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var parts []string
		for _, b := range blocks {
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// Proxy is the live-traffic enforcement point: a reverse proxy in front of an
// upstream LLM or MCP endpoint that applies the gateway's gates to the actual
// request on the wire before forwarding it. It is the counterpart to the inline
// Server, which screens a request the caller declares to it: the Proxy screens
// the agent's real model/tool call, recovered from its headers and body, and a
// blocked request never reaches the upstream. The same three gates compose, first
// denial wins — the registry decision, the content guardrail, then the rate/cost
// limit — and every handled interaction is logged in the JSON-lines shape the
// trace evidence producer consumes, so what the proxy enforced rolls up as
// control evidence with no separate collection step.
type Proxy struct {
	Registry  registry.Registry
	Guardrail Guardrail
	Limiter   *Limiter
	// Upstream is the model/tool endpoint admitted requests are forwarded to.
	Upstream *url.URL
	// Extract recovers the gateway Request from the live HTTP request; defaults to
	// RequestFromHTTP when nil. It is a field so a deployment whose wire format
	// differs can supply its own mapping without changing the enforcement.
	Extract func(*http.Request) (Request, error)
	// Log receives one JSON object per handled interaction (JSON Lines); nil
	// disables logging.
	Log io.Writer
	// Now supplies the interaction timestamp and the limiter's clock; defaults to
	// time.Now when nil.
	Now func() time.Time

	mu sync.Mutex // serializes writes to Log
}

// ServeHTTP screens one live interaction and either forwards it to the upstream
// or blocks it. It recovers the gateway Request, runs the registry, guardrail,
// and limiter gates in order (first denial wins, and the limiter is charged only
// when the earlier gates pass, so a blocked request never draws down budget),
// logs the verdict, and on a denial replies 403 with the Decision without ever
// contacting the upstream. A request whose identity cannot be recovered is a 400.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	extract := p.Extract
	if extract == nil {
		extract = RequestFromHTTP
	}
	req, err := extract(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	decision := Decide(p.Registry, req)
	if decision.Allowed {
		decision = p.Guardrail.Screen(req.Input)
	}
	if decision.Allowed {
		decision = p.Limiter.Charge(req.Agent, req.Cost, clock(p.Now))
	}
	writeLogLine(p.Log, &p.mu, clock(p.Now), logEntry{
		ID:      req.ID,
		Agent:   req.Agent,
		Model:   req.Model,
		Prompt:  req.Prompt,
		Tools:   req.Tools,
		Phase:   "input",
		Allowed: decision.Allowed,
		Reason:  decision.Reason,
	})
	if !decision.Allowed {
		respond(w, decision)
		return
	}

	rp := httputil.NewSingleHostReverseProxy(p.Upstream)
	director := rp.Director
	rp.Director = func(req *http.Request) {
		director(req)
		// Address the upstream as its own host so TLS SNI and virtual-host
		// routing resolve to the model endpoint, not the proxy's caller-facing
		// host.
		req.Host = p.Upstream.Host
	}
	// When a content guardrail is configured, screen the upstream's response body
	// before it reaches the agent — the same guardrail that screens the request,
	// applied to the generated output, so a secret or prohibited content the model
	// returns is caught on the way back. This buffers the response body; an
	// unguarded proxy sets no ModifyResponse and streams the response through
	// untouched.
	if p.Guardrail.active() {
		logOutput := func(decision Decision) {
			writeLogLine(p.Log, &p.mu, clock(p.Now), logEntry{
				ID:      req.ID,
				Agent:   req.Agent,
				Model:   req.Model,
				Prompt:  req.Prompt,
				Phase:   "output",
				Allowed: decision.Allowed,
				Reason:  decision.Reason,
			})
		}
		rp.ModifyResponse = func(resp *http.Response) error {
			// A streamed (Server-Sent Events) response is screened incrementally:
			// each event is released to the agent only after it passes the
			// guardrail, and the stream is cut at the first event a rule catches,
			// so the proxy buffers one event rather than the whole response. The
			// status line has already gone out as the upstream's 200, so a block
			// here truncates the stream before the offending event rather than
			// turning into a 403 — the secret still never reaches the agent.
			if isEventStream(resp) {
				resp.Body = &screeningReader{src: resp.Body, guard: p.Guardrail, logOutput: logOutput}
				return nil
			}

			// A non-streamed response is buffered and screened whole, so a dirty
			// body can be replaced with a 403 before any of it reaches the agent.
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()

			decision := p.Guardrail.Screen(string(body))
			logOutput(decision)

			if !decision.Allowed {
				// Replace the secret-bearing response with the Decision and a
				// fresh header set, so neither the blocked content nor any
				// upstream header reaches the agent.
				payload, _ := json.Marshal(decision)
				resp.StatusCode = http.StatusForbidden
				resp.Status = http.StatusText(http.StatusForbidden)
				resp.Body = io.NopCloser(bytes.NewReader(payload))
				resp.ContentLength = int64(len(payload))
				resp.Header = http.Header{}
				resp.Header.Set("Content-Type", "application/json")
				resp.Header.Set("Content-Length", strconv.Itoa(len(payload)))
				return nil
			}

			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			return nil
		}
	}
	rp.ServeHTTP(w, r)
}

// isEventStream reports whether the response is a Server-Sent Events stream, the
// shape a model uses to deliver a completion token by token. Such a response is
// screened event by event rather than buffered whole.
func isEventStream(resp *http.Response) bool {
	return strings.HasPrefix(strings.TrimSpace(resp.Header.Get("Content-Type")), "text/event-stream")
}

// screeningReader screens a streamed (SSE) response body incrementally. It reads
// from the upstream, splits the stream on SSE event boundaries (a blank line),
// and releases an event to the agent only once it passes the guardrail; at the
// first event a rule catches it cuts the stream — the dirty event and everything
// after it are withheld — and records the verdict exactly once. It buffers at
// most one in-flight event, so a long response is screened as it flows rather
// than held whole. A clean stream is forwarded unchanged and logged as allowed
// when it ends.
type screeningReader struct {
	src       io.ReadCloser
	guard     Guardrail
	logOutput func(Decision)

	pending []byte // bytes read from the upstream not yet split into an event
	ready   []byte // screened-clean bytes ready to hand to the agent
	done    bool   // no more bytes will be released (clean EOF or a block)
	blocked bool   // a rule fired; the stream is cut
	logged  bool   // the single output verdict has been recorded
}

func (s *screeningReader) Read(p []byte) (int, error) {
	for len(s.ready) == 0 && !s.done {
		buf := make([]byte, 4096)
		n, err := s.src.Read(buf)
		if n > 0 {
			s.pending = append(s.pending, buf[:n]...)
			s.drain(false)
		}
		if err != nil {
			if err == io.EOF {
				s.drain(true) // screen the final, unterminated event
				s.finish()
				break
			}
			return 0, err
		}
	}
	if len(s.ready) > 0 {
		n := copy(p, s.ready)
		s.ready = s.ready[n:]
		return n, nil
	}
	return 0, io.EOF
}

// drain screens every complete SSE event currently buffered, appending clean
// events to ready and stopping at the first dirty one. When final is set the
// trailing bytes (an event with no terminating blank line) are screened too.
func (s *screeningReader) drain(final bool) {
	const sep = "\n\n"
	for !s.done {
		idx := bytes.Index(s.pending, []byte(sep))
		if idx < 0 {
			break
		}
		event := s.pending[:idx+len(sep)]
		s.pending = s.pending[idx+len(sep):]
		s.screen(event)
	}
	if final && !s.done && len(s.pending) > 0 {
		s.screen(s.pending)
		s.pending = nil
	}
}

// screen releases a clean event to the agent, or blocks the stream on the first
// event a rule catches.
func (s *screeningReader) screen(event []byte) {
	if d := s.guard.Screen(string(event)); !d.Allowed {
		s.blocked = true
		s.done = true
		s.log(d)
		return
	}
	s.ready = append(s.ready, event...)
}

// finish records a clean stream's allowed verdict once it reaches EOF without a
// block.
func (s *screeningReader) finish() {
	s.done = true
	if !s.blocked {
		s.log(Decision{Allowed: true})
	}
}

func (s *screeningReader) log(d Decision) {
	if s.logged {
		return
	}
	s.logged = true
	s.logOutput(d)
}

func (s *screeningReader) Close() error { return s.src.Close() }
