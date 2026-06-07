package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/registry"
)

// Server is the inline runtime gateway: an http.Handler that admits or blocks
// each agent interaction against the registry's qualified surface before it runs,
// and appends every handled interaction to an append-only log. The log is the
// same shape evidence.FromAgentTraces consumes, so what the gateway enforced
// inline rolls up as control evidence with no separate collection step.
type Server struct {
	Registry registry.Registry
	// Guardrail screens request content after the registry check passes. Its zero
	// value screens nothing, so a server with no guardrail enforces registration
	// only.
	Guardrail Guardrail
	// Limiter enforces per-agent rate and cost budgets, the third gate after the
	// registry and guardrail. A nil limiter enforces no budget.
	Limiter *Limiter
	// Log receives one JSON object per handled interaction, newline-terminated
	// (JSON Lines). May be nil to disable logging.
	Log io.Writer
	// Now supplies the interaction timestamp; defaults to time.Now when nil.
	Now func() time.Time

	mu sync.Mutex // serializes writes to Log
}

// OutputRequest is a generated agent output presented to the gateway for response
// screening, after the interaction was admitted and ran. The model produced
// Output for the named agent and prompt; the guardrail screens that content the
// same way it screens input. The prompt is carried so the logged interaction is a
// well-formed trace the evidence path can attribute.
type OutputRequest struct {
	ID     string `json:"id"`
	Agent  string `json:"agent"`
	Prompt string `json:"prompt"`
	Output string `json:"output"`
}

// logEntry is one line of the interaction log. Its id/agent/prompt/tools/
// timestamp fields are exactly what evidence.FromAgentTraces reads; allowed and
// reason record the gateway's inline verdict for auditing the enforcement itself.
// Phase distinguishes the input-admission record from the output-screening record
// of the same interaction; Model records which model the request asked to call.
type logEntry struct {
	ID        string    `json:"id"`
	Agent     string    `json:"agent"`
	Model     string    `json:"model,omitempty"`
	Prompt    string    `json:"prompt"`
	Tools     []string  `json:"tools,omitempty"`
	Phase     string    `json:"phase,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason,omitempty"`
}

// ServeHTTP routes the gateway's two POST surfaces: /output screens a generated
// output through the guardrail, and any other path admits an interaction request.
// A non-POST is rejected before any decision.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/output" {
		s.serveOutput(w, r)
		return
	}
	s.serveDecide(w, r)
}

// serveDecide decodes an interaction Request, decides it against the registry and
// guardrail, records it to the log, and replies with the Decision: 200 when
// admitted, 403 when blocked. A malformed body is rejected before any decision.
func (s *Server) serveDecide(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}

	// The registry check decides whether the agent may act at all (including the
	// model allow-list); if it passes, the content guardrail decides whether this
	// request's input may pass; if that passes too, the limiter decides whether the
	// agent still has budget for it. The first denial wins, and only a request that
	// clears the first two gates is charged against the budget — a blocked request
	// consumes nothing.
	decision := Decide(s.Registry, req)
	if decision.Allowed {
		decision = s.Guardrail.Screen(req.Input)
	}
	if decision.Allowed {
		decision = s.Limiter.Charge(req.Agent, req.Cost, s.now())
	}
	s.writeLog(logEntry{
		ID:      req.ID,
		Agent:   req.Agent,
		Model:   req.Model,
		Prompt:  req.Prompt,
		Tools:   req.Tools,
		Phase:   "input",
		Allowed: decision.Allowed,
		Reason:  decision.Reason,
	})
	respond(w, decision)
}

// serveOutput decodes an OutputRequest and screens its generated content through
// the guardrail, recording the verdict (never the raw output) and replying 200
// when the output may pass, 403 when a guardrail rule catches it. Output screening
// is content-only: the agent already passed the input-admission decision, so the
// registry check is not repeated here.
func (s *Server) serveOutput(w http.ResponseWriter, r *http.Request) {
	var req OutputRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}

	decision := s.Guardrail.Screen(req.Output)
	s.writeLog(logEntry{
		ID:      req.ID,
		Agent:   req.Agent,
		Prompt:  req.Prompt,
		Phase:   "output",
		Allowed: decision.Allowed,
		Reason:  decision.Reason,
	})
	respond(w, decision)
}

// now returns the server's clock, defaulting to time.Now when Now is nil. It is
// the single time source for both the limiter charge and the log timestamp of an
// interaction, so a request's budget window and its logged time agree.
func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// respond writes a Decision as the HTTP reply: 200 when allowed, 403 when not.
func respond(w http.ResponseWriter, decision Decision) {
	status := http.StatusOK
	if !decision.Allowed {
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(decision)
}

// writeLog appends one interaction line to the log, if a log is configured. The
// entry never carries raw request input or output content, only the verdict, so
// the log cannot itself leak the sensitive data a guardrail caught. The timestamp
// is stamped here from Now (defaulting to time.Now).
func (s *Server) writeLog(entry logEntry) {
	if s.Log == nil {
		return
	}
	entry.Timestamp = s.now().UTC()
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.Log.Write(append(line, '\n'))
}
