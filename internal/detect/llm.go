// Package detect holds passive detectors: pure functions that look at an
// exchange that has already been forwarded and label it. They never touch
// the network and never change traffic.
//
// Everything they read is captured traffic, so it is untrusted input: every
// detector bounds how much it reads and must not panic on any byte sequence.
package detect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"strings"

	"github.com/dgtlmonk/sluice/internal/engine"
)

// LLM rule names, stored in exchanges.llm_reason (SPEC.md, AI security
// module, 1. LLM endpoint detection, basic flagging).
const (
	ReasonPath = "path" // request path is a well-known LLM API endpoint
	ReasonJSON = "json" // request body is a chat/completion-shaped JSON object
	ReasonSSE  = "sse"  // response is a text/event-stream (token streaming)
)

// MaxJSONBody is the most decoded request body the JSON rule will parse.
// Chat requests are small; a body larger than this is not flagged by the
// JSON rule at all, which keeps detection cheap and bounded.
const MaxJSONBody = 1 << 20

// llmPaths are the endpoints of the common LLM HTTP APIs:
// OpenAI (and the many "OpenAI-compatible" servers), Anthropic, and Ollama.
var llmPaths = map[string]bool{
	"/v1/chat/completions": true, // OpenAI Chat Completions
	"/v1/responses":        true, // OpenAI Responses
	"/v1/messages":         true, // Anthropic Messages
	"/v1/embeddings":       true, // OpenAI embeddings
	"/api/chat":            true, // Ollama chat
	"/api/generate":        true, // Ollama completion
}

// Input is what the LLM detector reads from one finished exchange.
type Input struct {
	Path       string // origin-form path, query included
	ReqHead    []byte // raw request head, start line through the blank line
	ReqBody    []byte // raw request body as on the wire (chunk framing included)
	ReqBodyCut bool   // the captured request body was truncated
	RespHead   []byte // raw response head; nil if no response
}

// LLM reports which rules flag the exchange as LLM traffic, as a
// comma-separated list in rule order (path, json, sse), or "" for none.
// Any match means is_llm.
func LLM(in Input) string {
	var reasons []string
	if isLLMPath(in.Path) {
		reasons = append(reasons, ReasonPath)
	}
	if isLLMRequestJSON(in.ReqHead, in.ReqBody, in.ReqBodyCut) {
		reasons = append(reasons, ReasonJSON)
	}
	if isEventStream(in.RespHead) {
		reasons = append(reasons, ReasonSSE)
	}
	return strings.Join(reasons, ",")
}

// isLLMPath matches the path only (the query is ignored), exactly or with a
// single trailing slash. Paths are case-sensitive in HTTP, so no folding.
func isLLMPath(target string) bool {
	path, _, _ := strings.Cut(target, "?")
	path, _, _ = strings.Cut(path, "#")
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return llmPaths[path]
}

// isLLMRequestJSON is the body rule: a JSON object with a "model" string and
// either a "messages" array whose items carry role and content, or a
// "prompt" field. The body is considered JSON if the Content-Type says so or
// if it starts with '{' after whitespace (clients often omit the type).
func isLLMRequestJSON(head, rawBody []byte, cut bool) bool {
	// A truncated stored copy is not the whole body. It was cut at 32 MB,
	// far above MaxJSONBody, so it would be "too big" anyway.
	if len(head) == 0 || len(rawBody) == 0 || cut {
		return false
	}
	// Re-parse the captured bytes with the engine's own parser. That gives
	// us the same header and framing decisions the proxy made, and a body
	// reader that undoes chunked framing.
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(head), bytes.NewReader(rawBody)))
	req, err := engine.ReadRequest(br, engine.DefaultLimits)
	if err != nil || req.Framing.Kind == engine.FramingNone {
		return false
	}
	if req.Headers.Has("Content-Encoding") {
		// gzip/br/zstd bodies would need decompressing first; that is M6.
		return false
	}
	// Read one byte past the cap so "exactly at the cap" and "over it" differ.
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxJSONBody+1))
	if len(body) > MaxJSONBody {
		return false
	}
	if err != nil {
		return false // framing did not decode
	}
	if !isJSONType(req.Headers.Get("Content-Type")) && !startsWithBrace(body) {
		return false
	}
	return looksLikeLLMRequest(body)
}

// llmRequest is the subset of an LLM request body the rule reads. Fields
// are json.RawMessage so a wrong type (e.g. "model": 3) is a non-match, not
// a decode error that hides the other fields.
type llmRequest struct {
	Model    json.RawMessage `json:"model"`
	Messages json.RawMessage `json:"messages"`
	Prompt   json.RawMessage `json:"prompt"`
}

type chatMessage struct {
	Role    json.RawMessage `json:"role"`
	Content json.RawMessage `json:"content"`
}

// looksLikeLLMRequest decodes body. encoding/json never panics on bad input;
// it just returns an error, which is a non-match.
func looksLikeLLMRequest(body []byte) bool {
	var r llmRequest
	if err := json.Unmarshal(body, &r); err != nil {
		return false
	}
	var model string
	if json.Unmarshal(r.Model, &model) != nil || model == "" {
		return false
	}
	if hasValue(r.Prompt) {
		return true
	}
	var msgs []chatMessage
	if json.Unmarshal(r.Messages, &msgs) != nil || len(msgs) == 0 {
		return false
	}
	for _, m := range msgs {
		if !hasValue(m.Role) || !hasValue(m.Content) {
			return false
		}
	}
	return true
}

// hasValue is true for any present, non-null JSON value. Content may be a
// string or an array of parts (images, tool results), so any type counts.
func hasValue(v json.RawMessage) bool {
	return len(v) > 0 && !bytes.Equal(v, []byte("null"))
}

func startsWithBrace(b []byte) bool {
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && b[0] == '{'
}

// isJSONType accepts application/json and any +json suffix type.
func isJSONType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// isEventStream is the response rule: Content-Type text/event-stream, any
// case, parameters (charset) ignored. Server-Sent Events is how every major
// LLM API streams tokens.
func isEventStream(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	// The method only matters for body framing, which this rule ignores.
	resp, err := engine.ReadResponse(bufio.NewReader(bytes.NewReader(head)), engine.DefaultLimits, "GET")
	if err != nil {
		return false
	}
	mt, _, err := mime.ParseMediaType(resp.Headers.Get("Content-Type"))
	return err == nil && mt == "text/event-stream"
}
