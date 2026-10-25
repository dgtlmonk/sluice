package detect

import (
	"fmt"
	"strings"
	"testing"
)

// reqHead builds a request head with Content-Length (or chunked when cl < 0).
func reqHead(path, contentType string, cl int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\nHost: origin.test\r\n", path)
	if contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	}
	if cl < 0 {
		b.WriteString("Transfer-Encoding: chunked\r\n")
	} else {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", cl)
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

func jsonReq(path, ct, body string) Input {
	return Input{Path: path, ReqHead: reqHead(path, ct, len(body)), ReqBody: []byte(body)}
}

func respHead(contentType string) []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nContent-Length: 0\r\n\r\n")
}

// chunk frames body as two chunks plus the last-chunk, as on the wire.
func chunk(body string) string {
	half := len(body) / 2
	return fmt.Sprintf("%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n", half, body[:half], len(body)-half, body[half:])
}

const chatBody = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`

func TestLLM(t *testing.T) {
	huge := `{"model":"m","prompt":"` + strings.Repeat("a", MaxJSONBody) + `"}`
	tests := []struct {
		name string
		in   Input
		want string
	}{
		// path rule
		{"openai chat path", Input{Path: "/v1/chat/completions"}, "path"},
		{"responses path", Input{Path: "/v1/responses"}, "path"},
		{"anthropic path", Input{Path: "/v1/messages"}, "path"},
		{"embeddings path", Input{Path: "/v1/embeddings"}, "path"},
		{"ollama chat path", Input{Path: "/api/chat"}, "path"},
		{"ollama generate path", Input{Path: "/api/generate"}, "path"},
		{"path trailing slash", Input{Path: "/v1/messages/"}, "path"},
		{"path with query", Input{Path: "/api/chat?stream=true"}, "path"},
		{"path prefix only", Input{Path: "/v1/messages/batches"}, ""},
		{"path query lookalike", Input{Path: "/search?q=/v1/messages"}, ""},
		{"path case differs", Input{Path: "/V1/Messages"}, ""},
		{"root path", Input{Path: "/"}, ""},

		// JSON rule
		{"chat json", jsonReq("/chat", "application/json", chatBody), "json"},
		{"prompt json", jsonReq("/gen", "application/json; charset=utf-8", `{"model":"llama3","prompt":"why?"}`), "json"},
		{"json no content-type", jsonReq("/gen", "", "  \n"+chatBody), "json"},
		{"json text/plain but brace", jsonReq("/gen", "text/plain", chatBody), "json"},
		{"content parts array", jsonReq("/gen", "application/json",
			`{"model":"claude","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`), "json"},
		{"chunked chat json", Input{Path: "/chat", ReqHead: reqHead("/chat", "application/json", -1), ReqBody: []byte(chunk(chatBody))}, "json"},
		{"path and json", jsonReq("/v1/chat/completions", "application/json", chatBody), "path,json"},
		{"normal json api", jsonReq("/v2/users", "application/json", `{"name":"ada","role":"admin"}`), ""},
		{"model without messages", jsonReq("/cars", "application/json", `{"model":"civic","year":2020}`), ""},
		{"messages without model", jsonReq("/chat", "application/json", `{"messages":[{"role":"user","content":"hi"}]}`), ""},
		{"messages missing role", jsonReq("/chat", "application/json", `{"model":"m","messages":[{"content":"hi"}]}`), ""},
		{"messages empty", jsonReq("/chat", "application/json", `{"model":"m","messages":[]}`), ""},
		{"messages not array", jsonReq("/chat", "application/json", `{"model":"m","messages":"hi"}`), ""},
		{"model not string", jsonReq("/chat", "application/json", `{"model":3,"prompt":"x"}`), ""},
		{"prompt null", jsonReq("/chat", "application/json", `{"model":"m","prompt":null}`), ""},
		{"invalid json", jsonReq("/chat", "application/json", `{"model":"m","prompt":`), ""},
		{"json array", jsonReq("/chat", "application/json", `[`+chatBody+`]`), ""},
		{"html body", jsonReq("/form", "text/html", `<html>{"model":"m","prompt":"x"}</html>`), ""},
		{"huge body", jsonReq("/gen", "application/json", huge), ""},
		{"truncated capture", Input{Path: "/c", ReqHead: reqHead("/c", "application/json", len(chatBody)), ReqBody: []byte(chatBody), ReqBodyCut: true}, ""},
		{"gzip body", Input{Path: "/c", ReqHead: []byte("POST /c HTTP/1.1\r\nHost: o\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n"), ReqBody: []byte("{}")}, ""},
		{"bad chunk framing", Input{Path: "/c", ReqHead: reqHead("/c", "application/json", -1), ReqBody: []byte("zz\r\n" + chatBody)}, ""},
		{"garbage head", Input{Path: "/c", ReqHead: []byte("\x00\xff garbage"), ReqBody: []byte(chatBody)}, ""},
		{"empty", Input{}, ""},

		// SSE rule
		{"sse", Input{Path: "/stream", RespHead: respHead("text/event-stream")}, "sse"},
		{"sse case and params", Input{Path: "/stream", RespHead: respHead("Text/Event-Stream; charset=utf-8")}, "sse"},
		{"sse-like wrong type", Input{Path: "/stream", RespHead: respHead("text/event-stream-ish")}, ""},
		{"ndjson stream", Input{Path: "/stream", RespHead: respHead("application/x-ndjson")}, ""},
		{"plain text", Input{Path: "/stream", RespHead: respHead("text/plain")}, ""},
		{"all three", Input{Path: "/v1/chat/completions", ReqHead: reqHead("/v1/chat/completions", "application/json", len(chatBody)),
			ReqBody: []byte(chatBody), RespHead: respHead("text/event-stream")}, "path,json,sse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LLM(tt.in); got != tt.want {
				t.Errorf("LLM() = %q, want %q", got, tt.want)
			}
		})
	}
}

// FuzzLLM checks the detector never panics on arbitrary captured bytes.
func FuzzLLM(f *testing.F) {
	f.Add("/v1/messages", string(reqHead("/c", "application/json", len(chatBody))), chatBody, string(respHead("text/event-stream")))
	f.Add("/", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", "5\r\n{\"a\"", "HTTP/1.1 200 OK\r\n\r\n")
	f.Fuzz(func(_ *testing.T, path, head, body, resp string) {
		_ = LLM(Input{Path: path, ReqHead: []byte(head), ReqBody: []byte(body), RespHead: []byte(resp)})
	})
}
