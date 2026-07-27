package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Byte limits for the enforcement path. Without them a single request or
// response can exhaust the proxy's memory before any gate has run — the read
// itself is the denial of service.
const (
	// MaxRequestBytes bounds a request body the proxy will accept and screen.
	MaxRequestBytes = 8 << 20
	// MaxResponseBytes bounds a buffered (non-streamed) upstream response. Past
	// this the response is blocked rather than buffered, so the proxy fails
	// closed instead of failing large.
	MaxResponseBytes = 8 << 20
	// maxPendingBytes bounds the in-flight buffer for a streamed response. An
	// upstream that never emits an event boundary would otherwise accumulate
	// without limit.
	maxPendingBytes = 1 << 20
	// overlapBytes is how much recently-released text is retained and re-screened
	// alongside the next event, so a pattern split across event boundaries is
	// still caught. It must exceed the longest pattern a rule can match.
	overlapBytes = 256
)

// screenable renders a body as the text the guardrail should see. A JSON body is
// DECODED first: screening raw JSON bytes lets \u-escaping hide a match that the
// agent's own parser will happily reconstruct. Every string in the document is
// collected, wherever it sits — a secret does not become safe by moving from
// `messages[].content` to a tool result, a system prompt, or a field this proxy
// has never heard of. The raw bytes are screened too, so a pattern that spans
// structure, or a body that is not JSON at all, is still caught.
func screenable(body []byte) string {
	values, err := jsonStringValues(body)
	if err != nil {
		return string(body)
	}
	// Joined without a separator as well as with one: adjacent string values are
	// exactly how a chunked payload reassembles, and a separator between them
	// would break a pattern that spans the join.
	joined := strings.Join(values, "")
	return joined + "\n" + strings.Join(values, "\n") + "\n" + string(body)
}

// jsonStringValues returns every string VALUE in a JSON document, in document
// order. Object keys are excluded and the order is the document's, not a map's:
// decoding into map[string]any and ranging over it would emit the values in Go's
// randomised iteration order, which breaks the adjacency this relies on to catch
// a pattern split across chunks.
func jsonStringValues(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out []string
	if err := scanStrings(dec, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func scanStrings(dec *json.Decoder, out *[]string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			for dec.More() {
				if _, err := dec.Token(); err != nil { // key, not screened as a value
					return err
				}
				if err := scanStrings(dec, out); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := scanStrings(dec, out); err != nil {
					return err
				}
			}
		default:
			return nil // a closing delimiter consumed by the caller
		}
		if _, err := dec.Token(); err != nil { // closing delimiter
			return err
		}
	case string:
		*out = append(*out, v)
	}
	return nil
}

// rejectAmbiguousKeys fails a JSON body whose objects contain the same key more
// than once, comparing case-insensitively.
//
// encoding/json matches object keys case-insensitively and takes the LAST match,
// so {"model":"forbidden","Model":"allowed"} shows this proxy "allowed" while a
// strict upstream parser reads "forbidden". Any gate keyed on such a body decides
// on a different value than the one that will actually be served, so the body is
// rejected rather than guessed at.
func rejectAmbiguousKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanAmbiguous(dec); err != nil {
		return err
	}
	return nil
}

func scanAmbiguous(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}

	switch delim {
	case '{':
		seen := map[string]string{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("malformed object key")
			}
			lower := strings.ToLower(key)
			if prev, dup := seen[lower]; dup {
				return fmt.Errorf("ambiguous body: keys %q and %q collide; "+
					"the gateway and the upstream would read different values", prev, key)
			}
			seen[lower] = key
			if err := scanAmbiguous(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := scanAmbiguous(dec); err != nil {
				return err
			}
		}
	}

	// Consume the matching closing delimiter.
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// eventText renders one SSE event as the decoded text the agent will ultimately
// see. Each `data:` payload is decoded when it is JSON so that token-by-token
// deltas concatenate into the same string the agent's parser reconstructs.
func eventText(event []byte) string {
	var parts []string
	for _, line := range strings.Split(string(event), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		values, err := jsonStringValues([]byte(payload))
		if err != nil {
			parts = append(parts, payload)
			continue
		}
		parts = append(parts, strings.Join(values, ""))
	}
	return strings.Join(parts, "")
}

// findEventEnd locates the end of the first complete SSE event in buf, returning
// its exclusive end offset and whether one was found.
//
// SSE permits "\n\n", "\r\n\r\n" and "\r\r" as the event terminator. Recognising
// only "\n\n" meant a CRLF upstream never matched, so nothing was released and
// the whole stream accumulated in memory until EOF.
func findEventEnd(buf []byte) (int, bool) {
	best := -1
	bestLen := 0
	for _, sep := range []string{"\r\n\r\n", "\n\n", "\r\r"} {
		if i := bytes.Index(buf, []byte(sep)); i >= 0 {
			if best < 0 || i < best || (i == best && len(sep) > bestLen) {
				best, bestLen = i, len(sep)
			}
		}
	}
	if best < 0 {
		return 0, false
	}
	return best + bestLen, true
}

// tailBytes returns the last n bytes of b.
func tailBytes(b []byte, n int) []byte {
	if len(b) <= n {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	out := make([]byte, n)
	copy(out, b[len(b)-n:])
	return out
}
