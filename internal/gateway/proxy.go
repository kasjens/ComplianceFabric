package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
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
	// HeaderToken carries the agent's shared secret when the proxy is configured
	// with AgentTokens. It is what turns the agent header from a claim into a
	// credential.
	HeaderToken = "X-Fabric-Token"
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
	// This is the live wire: an undeclared model can still resolve upstream, so
	// a pinned agent must state one.
	req := Request{Agent: agent, Prompt: r.Header.Get(HeaderPrompt), RequireDeclaredModel: true}

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

	// Bound the read: without a limit a multi-gigabyte body is pulled entirely
	// into memory before any gate runs.
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil {
		return Request{}, err
	}
	if len(body) > MaxRequestBytes {
		return Request{}, fmt.Errorf("request body exceeds the %d byte limit", MaxRequestBytes)
	}
	// Leave the consumed body readable for the reverse proxy to forward verbatim.
	r.Body = io.NopCloser(bytes.NewReader(body))

	if len(bytes.TrimSpace(body)) == 0 {
		return req, nil
	}

	// A body whose keys collide case-insensitively would be read differently by
	// this proxy and by the upstream, so no gate on it can be trusted.
	if err := rejectAmbiguousKeys(body); err != nil {
		return Request{}, err
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
		// Legacy OpenAI function-calling shape. Without it a caller using the
		// older field skips tool qualification entirely.
		Functions []struct {
			Name string `json:"name"`
		} `json:"functions"`
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
	for _, f := range payload.Functions {
		if f.Name != "" {
			req.Tools = append(req.Tools, f.Name)
		}
	}

	// Screen the WHOLE decoded body, not a structured extract of it. Reducing the
	// request to the message fields this struct happens to model meant anything
	// carried elsewhere — a tool result, a tool's arguments, a top-level system
	// prompt, a newer API's input field, a block type that did not exist when
	// this was written — was screened as the empty string and allowed.
	req.Input = screenable(body)
	return req, nil
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
	// AgentTokens maps an agent id to the shared secret that proves a caller is
	// that agent. When it is non-nil every request must present a matching
	// X-Fabric-Token, so an agent's qualified surface and budget can no longer be
	// claimed by anyone who can reach the listener.
	//
	// When it is nil the agent header is an UNAUTHENTICATED assertion and the
	// proxy is only as safe as its network. That is a deployment decision, not an
	// oversight — see ADR-0008 — but it means the listener must be reachable only
	// by trusted callers (loopback, or behind an mTLS sidecar that terminates
	// client certificates).
	AgentTokens map[string]string
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

	// Give the interaction an id if the extractor did not. The input and output
	// phases of one interaction are logged as separate lines, and the id is what
	// binds them: without it the evidence producer cannot tell two phases of one
	// interaction from two interactions, and every proxied call counts twice.
	if req.ID == "" {
		req.ID = newInteractionID()
	}

	// Authenticate the asserted identity before any gate keyed on it runs. Every
	// downstream decision — registry qualification, the model and tool
	// allow-lists, the rate and cost budget — trusts req.Agent, so if the claim
	// is unproven all of them are.
	if !p.authenticate(req.Agent, r.Header.Get(HeaderToken)) {
		decision := Decision{Allowed: false, Reason: "agent " + req.Agent + " failed authentication"}
		writeLogLine(p.Log, &p.mu, clock(p.Now), logEntry{
			ID: req.ID, Agent: req.Agent, Prompt: req.Prompt, Phase: "input",
			Allowed: false, Reason: decision.Reason,
		})
		payload, _ := json.Marshal(decision)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(payload)
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
			body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
			if err != nil {
				return err
			}
			_ = resp.Body.Close()

			// An oversized response is blocked rather than buffered: failing
			// closed is the point of screening the response at all.
			if len(body) > MaxResponseBytes {
				decision := Decision{Allowed: false, Reason: fmt.Sprintf(
					"upstream response exceeds the %d byte screening limit", MaxResponseBytes)}
				logOutput(decision)
				blockResponse(resp, decision)
				return nil
			}

			// Screened DECODED: the request was screened as decoded text while the
			// response was screened as raw JSON, so a \u-escaped secret matched
			// nothing here yet was reconstructed by the agent's own parser.
			decision := p.Guardrail.Screen(screenable(body))
			logOutput(decision)

			if !decision.Allowed {
				blockResponse(resp, decision)
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

// newInteractionID returns a random id binding the phases of one interaction.
// It is an opaque correlation handle, not a security token; if the random source
// fails it degrades to a fixed value, which correlates worse but never blocks a
// request over a logging concern.
func newInteractionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "interaction"
	}
	return hex.EncodeToString(b[:])
}

// authenticate reports whether the caller may act as the named agent. With no
// AgentTokens configured every caller passes, which is the documented
// trusted-network posture; with tokens configured the agent must be known and
// present its secret. The comparison is constant-time so a token cannot be
// recovered by timing.
func (p *Proxy) authenticate(agent, token string) bool {
	if p.AgentTokens == nil {
		return true
	}
	want, ok := p.AgentTokens[agent]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}

// blockResponse replaces a response with the Decision that blocked it, under a
// fresh header set, so neither the withheld content nor any upstream header
// reaches the agent.
func blockResponse(resp *http.Response, decision Decision) {
	payload, _ := json.Marshal(decision)
	resp.StatusCode = http.StatusForbidden
	resp.Status = http.StatusText(http.StatusForbidden)
	resp.Body = io.NopCloser(bytes.NewReader(payload))
	resp.ContentLength = int64(len(payload))
	resp.Header = http.Header{}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(payload)))
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

	// textTail is the decoded tail of recently released events, re-screened
	// alongside the next event so a pattern split across an event boundary is
	// still caught. Token-by-token streaming is exactly how a model emits text,
	// so without it "AKIA" and "IOSFODNN7EXAMPLE" pass as two clean events and
	// the agent reassembles the key.
	textTail []byte
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
	for !s.done {
		end, ok := findEventEnd(s.pending)
		if !ok {
			break
		}
		event := s.pending[:end]
		s.pending = s.pending[end:]
		s.screen(event)
	}

	// An upstream that never emits a boundary must not be able to grow this
	// buffer without limit.
	if !s.done && !final && len(s.pending) > maxPendingBytes {
		s.blocked = true
		s.done = true
		s.pending = nil
		s.log(Decision{Allowed: false, Reason: fmt.Sprintf(
			"upstream stream exceeded the %d byte event buffer without an event boundary", maxPendingBytes)})
		return
	}

	if final && !s.done && len(s.pending) > 0 {
		s.screen(s.pending)
		s.pending = nil
	}
}

// screen releases a clean event to the agent, or blocks the stream on the first
// event a rule catches.
//
// The event is screened as DECODED text joined to the tail of what was already
// released, so a pattern spanning two events is caught even though neither event
// matches alone. The raw event is screened too, for streams that are not JSON.
//
// Residual, by nature: bytes already handed to the agent cannot be recalled. The
// overlap check stops the REST of the stream, so the full pattern is never
// completed, but streaming enforcement is best-effort in a way buffered
// screening is not.
func (s *screeningReader) screen(event []byte) {
	probe := string(s.textTail) + eventText(event)

	if d := s.guard.Screen(probe); !d.Allowed {
		s.blocked = true
		s.done = true
		s.log(d)
		return
	}
	if d := s.guard.Screen(string(event)); !d.Allowed {
		s.blocked = true
		s.done = true
		s.log(d)
		return
	}

	s.ready = append(s.ready, event...)
	s.textTail = tailBytes([]byte(probe), overlapBytes)
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
