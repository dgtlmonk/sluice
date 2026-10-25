// Package testorigin is a local, test-only HTTP/1.1 origin server. It exists
// so proxy integration tests never hit the public internet. It uses net/http
// on purpose: this is the reference-oracle side, not the proxy path.
//
// Every body is deterministic, so a direct fetch and a proxied fetch can be
// byte-diffed (for example with curl).
//
// Endpoints:
//
//	GET /content-length  Fixed body framed by Content-Length.
//	GET /chunked         Body sent with Transfer-Encoding: chunked; each of
//	                     ChunkParts is flushed as its own chunk.
//	GET /keep-alive      Small Content-Length body; the connection stays open
//	                     so 2+ requests can share one TCP connection.
//	GET /close           Raw response with Connection: close and no
//	                     Content-Length or Transfer-Encoding. The body ends
//	                     when the server closes the socket (close-delimited,
//	                     RFC 9112 section 6.3 rule 8).
//	GET /sse             text/event-stream; SSEEvents are flushed one by one
//	                     with SSEDelay between them, so tests can prove events
//	                     arrive incrementally rather than buffered.
//	POST /v1/chat/completions
//	                     LLM-shaped endpoint: reads the whole request body
//	                     (Content-Length or chunked) and answers ChatReply
//	                     as JSON with Content-Length. Used by load tests.
package testorigin

import (
	"bufio"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"
)

// Endpoint paths.
const (
	PathContentLength = "/content-length"
	PathChunked       = "/chunked"
	PathKeepAlive     = "/keep-alive"
	PathClose         = "/close"
	PathSSE           = "/sse"
	PathChat          = "/v1/chat/completions"
)

// Deterministic bodies.
const (
	ContentLengthBody = "content-length body: the quick brown fox jumps over the lazy dog\n"
	KeepAliveBody     = "keep-alive ok\n"
	CloseBody         = "close-delimited body: read until EOF\n"
	SSEDelay          = 50 * time.Millisecond
	ChatReply         = `{"id":"cmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`
)

// ChunkParts are written and flushed one at a time by /chunked.
var ChunkParts = []string{"chunk-one\n", "chunk-two\n", "chunk-three\n"}

// SSEEvents are the data payloads emitted by /sse, in order.
var SSEEvents = []string{"tok-1", "tok-2", "tok-3", "tok-4"}

// ChunkedBody is the decoded body of /chunked.
func ChunkedBody() string { return strings.Join(ChunkParts, "") }

// SSEBody is the full decoded body of /sse.
func SSEBody() string {
	var b strings.Builder
	for _, e := range SSEEvents {
		b.WriteString(sseFrame(e))
	}
	return b.String()
}

// An SSE event is "data: <payload>" terminated by a blank line.
func sseFrame(data string) string { return "data: " + data + "\n\n" }

// Handler returns the mux serving all endpoints.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathContentLength, handleContentLength)
	mux.HandleFunc("GET "+PathChunked, handleChunked)
	mux.HandleFunc("GET "+PathKeepAlive, handleKeepAlive)
	mux.HandleFunc("GET "+PathClose, handleClose)
	mux.HandleFunc("GET "+PathSSE, handleSSE)
	mux.HandleFunc("POST "+PathChat, handleChat)
	return mux
}

// Start serves Handler on 127.0.0.1:0 (loopback, OS-chosen port). It returns
// the host:port address and a stop func that closes the server.
func Start() (addr string, stop func()) {
	srv := httptest.NewServer(Handler()) // httptest binds 127.0.0.1:0.
	return srv.Listener.Addr().String(), srv.Close
}

// TLSServerName is a DNS name the StartTLS certificate is valid for. The
// listener is still 127.0.0.1; tests dial that address and send this name as
// SNI, so nothing is resolved through DNS.
const TLSServerName = "example.com"

// StartTLS serves Handler over HTTPS on 127.0.0.1:0. The certificate comes
// from httptest: self-signed, so it is its own CA, valid for 127.0.0.1, ::1
// and TLSServerName. roots trusts exactly that certificate, so a proxy under
// test can verify the origin without touching the system trust store.
// The server offers only http/1.1 via ALPN (httptest does not enable h2
// unless asked).
func StartTLS() (addr string, roots *x509.CertPool, stop func()) {
	srv := httptest.NewTLSServer(Handler())
	roots = x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv.Listener.Addr().String(), roots, srv.Close
}

func writeFixed(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write([]byte(body))
}

func handleContentLength(w http.ResponseWriter, _ *http.Request) {
	writeFixed(w, ContentLengthBody)
}

func handleKeepAlive(w http.ResponseWriter, _ *http.Request) {
	writeFixed(w, KeepAliveBody)
}

// net/http switches to chunked encoding when no Content-Length is set and the
// handler flushes before finishing; each Flush emits the buffered bytes as a
// chunk ("<hex-size>\r\n<data>\r\n"), ending with "0\r\n\r\n".
func handleChunked(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "flush unsupported", http.StatusInternalServerError)
		return
	}
	for _, part := range ChunkParts {
		_, _ = w.Write([]byte(part))
		flusher.Flush()
	}
}

// net/http would never emit a close-delimited body itself, so hijack the
// socket and write the response bytes by hand, then close.
func handleClose(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	writeRawClose(buf, r.Method == http.MethodHead)
}

// A response to HEAD never carries content (RFC 9110 section 9.3.2): the
// head is the same as for GET, but the server closes right after it. The
// mux's "GET" pattern also matches HEAD, so the hijacked path must check.
func writeRawClose(buf *bufio.ReadWriter, headOnly bool) {
	head := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	_, _ = buf.WriteString(head)
	if !headOnly {
		_, _ = buf.WriteString(CloseBody)
	}
	_ = buf.Flush()
}

// handleChat drains the request body first, so the proxy has forwarded all
// of it (keep-alive stays usable), then answers a fixed JSON completion.
func handleChat(w http.ResponseWriter, r *http.Request) {
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(ChatReply)))
	_, _ = w.Write([]byte(ChatReply))
}

func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "flush unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	for i, e := range SSEEvents {
		if i > 0 {
			select {
			case <-time.After(SSEDelay):
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte(sseFrame(e)))
		flusher.Flush()
	}
}
