package engine

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/dgtlmonk/sluice/internal/testorigin"
)

func br(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

// --- Request head (no framing decision involved) ---

func TestReadRequestHead_OK(t *testing.T) {
	raw := "POST /a?b=1 HTTP/1.1\r\nHost: x\r\nX-Dup: 1\r\nx-dup:  2 \r\n\r\nBODY"
	r := br(raw)
	req, err := readRequestHead(r, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Target != "/a?b=1" || req.Proto != "HTTP/1.1" || req.Minor != 1 {
		t.Fatalf("bad request line: %+v", req)
	}
	if got := req.Headers.Values("X-DUP"); len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Fatalf("Values = %q", got)
	}
	if req.Headers[2].Name != "x-dup" {
		t.Fatalf("name case not preserved: %q", req.Headers[2].Name)
	}
	if string(req.RawHead) != strings.TrimSuffix(raw, "BODY") {
		t.Fatalf("RawHead = %q", req.RawHead)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "BODY" {
		t.Fatalf("head over-read; rest = %q", rest)
	}
}

func TestReadRequestHead_AbsoluteFormAndHTTP10(t *testing.T) {
	req, err := readRequestHead(br("GET http://h:5000/x HTTP/1.0\r\n\r\n"), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if req.Target != "http://h:5000/x" || req.Minor != 0 {
		t.Fatalf("%+v", req)
	}
}

func TestReadRequestHead_Rejections(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"SPEC: bare LF ends request line", "GET / HTTP/1.1\nHost: x\r\n\r\n", ErrBareLF},
		{"SPEC: bare LF ends header", "GET / HTTP/1.1\r\nHost: x\n\r\n", ErrBareLF},
		{"SPEC: bare LF final empty line", "GET / HTTP/1.1\r\nHost: x\r\n\n", ErrBareLF},
		{"SPEC: bare CR in header value", "GET / HTTP/1.1\r\nHost: x\ry\r\n\r\n", ErrBareCR},
		{"SPEC: bare CR in request line", "GET /\r HTTP/1.1\r\nHost: x\r\n\r\n", ErrBareCR},
		{"SPEC: obs-fold SP", "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n 2\r\n\r\n", ErrObsFold},
		{"SPEC: obs-fold HTAB", "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n\t2\r\n\r\n", ErrObsFold},
		{"space before colon", "GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n\r\n", ErrSpaceBeforeCol},
		{"empty field name", "GET / HTTP/1.1\r\nHost: x\r\n: v\r\n\r\n", ErrHeaderName},
		{"no colon", "GET / HTTP/1.1\r\nHost: x\r\nnocolon\r\n\r\n", ErrHeaderName},
		{"non-token name", "GET / HTTP/1.1\r\nHost: x\r\nX(A): v\r\n\r\n", ErrHeaderName},
		{"NUL in value", "GET / HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\n\r\n", ErrHeaderValue},
		{"double space in request line", "GET  / HTTP/1.1\r\nHost: x\r\n\r\n", ErrRequestLine},
		{"missing version", "GET /\r\nHost: x\r\n\r\n", ErrRequestLine},
		{"bad method", "G(T / HTTP/1.1\r\nHost: x\r\n\r\n", ErrRequestLine},
		{"lowercase version", "GET / http/1.1\r\nHost: x\r\n\r\n", ErrRequestLine},
		{"HTTP/2.0 -> 505", "GET / HTTP/2.0\r\nHost: x\r\n\r\n", ErrUnsupportedV},
		{"HTTP/1.1 missing Host", "GET / HTTP/1.1\r\n\r\n", ErrHost},
		{"HTTP/1.1 two Hosts", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", ErrHost},
		// Found by FuzzReadRequestDifferential: duplicate Host was only
		// checked on HTTP/1.1.
		{"HTTP/1.0 two Hosts", "GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n", ErrHost},
		{"truncated head", "GET / HTTP/1.1\r\nHost: x\r\n", io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := readRequestHead(br(c.raw), DefaultLimits)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestReadRequestHead_CleanEOF(t *testing.T) {
	if _, err := readRequestHead(br(""), DefaultLimits); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

func TestLimits(t *testing.T) {
	lim := Limits{MaxStartLine: 32, MaxHeaderCount: 3, MaxHeaderBytes: 128}
	cases := []struct {
		name   string
		raw    string
		want   error
		status int
	}{
		{"request line too long -> 400", "GET /" + strings.Repeat("a", 40) + " HTTP/1.1\r\n\r\n", ErrLineTooLong, 400},
		{"too many headers -> 431", "GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", ErrTooManyHeader, 431},
		{"header section too big -> 431", "GET / HTTP/1.1\r\nHost: x\r\nA: " + strings.Repeat("v", 150) + "\r\n\r\n", ErrHeaderTooBig, 431},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := readRequestHead(br(c.raw), lim)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Status != c.status {
				t.Fatalf("status = %v, want %d", pe, c.status)
			}
		})
	}
	// At the limit is fine.
	if _, err := readRequestHead(br("GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\n\r\n"), lim); err != nil {
		t.Fatalf("at-limit head rejected: %v", err)
	}
}

// --- Response head and no-body rules (no framing decision involved) ---

func TestReadResponseHead(t *testing.T) {
	cases := []struct {
		raw    string
		code   int
		reason string
		err    error
	}{
		{raw: "HTTP/1.1 200 OK\r\n\r\n", code: 200, reason: "OK"},
		{raw: "HTTP/1.1 404 Not Found\r\n\r\n", code: 404, reason: "Not Found"},
		{raw: "HTTP/1.1 204\r\n\r\n", code: 204},
		{raw: "HTTP/1.1 204 \r\n\r\n", code: 204},
		{raw: "HTTP/1.1 20 OK\r\n\r\n", err: ErrStatusLine},
		{raw: "HTTP/1.1 600 X\r\n\r\n", err: ErrStatusLine},
		{raw: "HTTP/1.1 2x0 X\r\n\r\n", err: ErrStatusLine},
		{raw: "HTTX/1.1 200 OK\r\n\r\n", err: ErrStatusLine},
		{raw: "HTTP/1.1 200 OK\nX: 1\r\n\r\n", err: ErrBareLF},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			resp, err := readResponseHead(br(c.raw), DefaultLimits)
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("err = %v, want %v", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != c.code || resp.Reason != c.reason {
				t.Fatalf("%d %q", resp.StatusCode, resp.Reason)
			}
		})
	}
}

// No-body responses ignore CL/TE entirely and never consult the framing
// decision, so the next message on the connection stays intact.
func TestReadResponse_NoBodyRules(t *testing.T) {
	cases := []struct {
		name, method, raw string
	}{
		{"HEAD with CL", "HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n"},
		{"100 continue", "POST", "HTTP/1.1 100 Continue\r\n\r\n"},
		{"204 with TE", "GET", "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n"},
		{"304 with CL", "GET", "HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n"},
		{"CONNECT 200", "CONNECT", "HTTP/1.1 200 Connection Established\r\n\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := br(c.raw + "NEXT")
			resp, err := ReadResponse(r, DefaultLimits, c.method)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Framing.Kind != FramingNone {
				t.Fatalf("framing = %v", resp.Framing.Kind)
			}
			if b, _ := io.ReadAll(resp.Body); len(b) != 0 {
				t.Fatalf("body = %q", b)
			}
			if rest, _ := io.ReadAll(r); string(rest) != "NEXT" {
				t.Fatalf("rest = %q", rest)
			}
		})
	}
}

// --- End to end: these go through decideBodyFraming and fail until it is
// implemented. ---

func TestReadRequest_Bodies(t *testing.T) {
	cases := []struct {
		name, raw, body string
	}{
		{"no body", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", ""},
		{"content-length", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello", "hello"},
		{"chunked", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", "hello"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := br(c.raw + "GET /next HTTP/1.1\r\nHost: x\r\n\r\n")
			req, err := ReadRequest(r, DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(req.Body)
			if err != nil || string(b) != c.body {
				t.Fatalf("body = %q, %v", b, err)
			}
			next, err := ReadRequest(r, DefaultLimits) // keep-alive: next message intact
			if err != nil || next.Target != "/next" {
				t.Fatalf("next = %+v, %v", next, err)
			}
		})
	}
}

func TestReadRequest_TEOnHTTP10(t *testing.T) {
	raw := "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	if _, err := ReadRequest(br(raw), DefaultLimits); !errors.Is(err, ErrTEOnHTTP10) {
		t.Fatalf("SPEC: err = %v, want ErrTEOnHTTP10", err)
	}
}

func TestReadRequest_SmugglingRejected(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	if _, err := ReadRequest(br(raw), DefaultLimits); !errors.Is(err, ErrCLAndTE) {
		t.Fatalf("err = %v, want ErrCLAndTE", err)
	}
}

func TestReadResponse_CloseDelimited(t *testing.T) {
	resp, err := ReadResponse(br("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil eof"), DefaultLimits, "GET")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "until eof" {
		t.Fatalf("body = %q", b)
	}
}

// Integration against internal/testorigin over a raw loopback socket.
func TestIntegration_TestOrigin(t *testing.T) {
	addr, stop := testorigin.Start()
	defer stop()
	cases := []struct {
		path, body string
		kind       FramingKind
	}{
		{testorigin.PathContentLength, testorigin.ContentLengthBody, FramingContentLength},
		{testorigin.PathChunked, testorigin.ChunkedBody(), FramingChunked},
		{testorigin.PathClose, testorigin.CloseBody, FramingCloseDelimited},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := io.WriteString(conn, "GET "+c.path+" HTTP/1.1\r\nHost: "+addr+"\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			resp, err := ReadResponse(bufio.NewReader(conn), DefaultLimits, "GET")
			if err != nil {
				t.Fatal(err)
			}
			if resp.Framing.Kind != c.kind {
				t.Fatalf("framing = %v, want %v", resp.Framing.Kind, c.kind)
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil || string(b) != c.body {
				t.Fatalf("body = %q, %v", b, err)
			}
		})
	}
}
