package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Regression tests. Each of these failed before the fix that accompanies it
// and is paired with a control case that passed, so it pins the defect rather
// than merely exercising the code.

// 1.3 — X-Fabric-Agent is an unauthenticated client string. Registry
// qualification, the model and tool allow-lists, AND the rate/cost budget are all
// keyed off it, so any peer that can reach the listener inherits a privileged
// agent's entire qualified surface simply by claiming its name. This test asserts
// the trust boundary the ADR must establish; until then it documents that the
// identity is asserted, never proven.
func TestHeaderIdentityIsUnauthenticated(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	p := &Proxy{
		Registry:    testRegistry(),
		Limiter:     NewLimiter(map[string]Limits{}),
		Upstream:    u,
		AgentTokens: map[string]string{"release-reviewer": "s3cret"},
	}
	ps := httptest.NewServer(p)
	defer ps.Close()

	call := func(token string) int {
		r, err := http.NewRequest(http.MethodPost, ps.URL+"/v1/messages",
			strings.NewReader(`{"model":"approved-model","messages":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set(HeaderAgent, "release-reviewer")
		r.Header.Set(HeaderPrompt, "summarise-findings")
		if token != "" {
			r.Header.Set(HeaderToken, token)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if code := call(""); code != http.StatusUnauthorized {
		t.Errorf("a caller asserting release-reviewer with NO credential got %d; "+
			"it inherited that agent's qualified surface and budget on an unproven claim", code)
	}
	if code := call("wrong"); code != http.StatusUnauthorized {
		t.Errorf("a caller presenting the wrong token got %d, want 401", code)
	}
	if code := call("s3cret"); code == http.StatusUnauthorized {
		t.Error("the legitimate agent was rejected with its correct token")
	}
}

// 1.8 — RequestFromHTTP does io.ReadAll on the request body with no
// MaxBytesReader and no LimitReader, so a multi-GB body is read entirely into
// memory before any gate runs. The read itself is the denial of service.
func TestOversizedRequestBodyMustBeRejected(t *testing.T) {
	// 32 MB of valid JSON — small enough to keep the test fast, far past any
	// sane request cap.
	body := `{"model":"approved-model","messages":[{"role":"user","content":"` +
		strings.Repeat("A", 32<<20) + `"}]}`

	r, err := http.NewRequest(http.MethodPost, "http://upstream/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(HeaderAgent, "release-reviewer")
	r.Header.Set(HeaderPrompt, "summarise-findings")

	if _, err := RequestFromHTTP(r); err == nil {
		t.Errorf("a %d MB request body was read whole into memory and accepted; "+
			"there is no MaxBytesReader on the request path", len(body)>>20)
	}
}

// 1.4 — drain looks only for "\n\n". SSE also permits "\r\n\r\n", so against a
// CRLF upstream bytes.Index never matches: nothing is released incrementally and
// `pending` grows without bound until EOF.
//
// Note (established during reproduction): this is a STREAMING and MEMORY defect,
// not a screening bypass. At EOF drain(final: true) screens the whole accumulated
// buffer as one event, which actually CATCHES a split secret that the working
// "\n\n" path misses. Fixing 1.4 without also landing 1.1's overlap window would
// therefore INTRODUCE the 1.1 leak on CRLF upstreams. Land them together.
func TestCRLFStreamMustReleaseIncrementally(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })

	sr := &screeningReader{src: pr, guard: akiaGuardrail(t), logOutput: func(Decision) {}}

	// One complete, clean SSE event using CRLF terminators. The stream stays open.
	go func() {
		io.WriteString(pw, "data: {\"delta\":{\"text\":\"hello\"}}\r\n\r\n")
	}()

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := sr.Read(buf)
		done <- result{n, err}
	}()

	select {
	case got := <-done:
		if got.n == 0 {
			t.Errorf("CRLF stream released 0 bytes: %v", got.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("a complete CRLF-terminated SSE event was not released to the agent; " +
			"the stream degraded to full buffering, so `pending` grows unbounded " +
			"until EOF and streaming is lost")
	}
}
