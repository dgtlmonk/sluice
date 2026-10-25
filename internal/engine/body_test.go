package engine

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestChunkedReader(t *testing.T) {
	cases := []struct {
		name, raw, body, rest string
		trailers              Headers
		err                   error
	}{
		{name: "two chunks", raw: "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", body: "hello world", trailers: Headers{}},
		{name: "hex uppercase + ext", raw: "A;foo=bar\r\n0123456789\r\n0\r\n\r\nNEXT", body: "0123456789", rest: "NEXT", trailers: Headers{}},
		{name: "BWS before ext", raw: "3 ;x\r\nabc\r\n0\r\n\r\n", body: "abc", trailers: Headers{}},
		{name: "trailers", raw: "3\r\nabc\r\n0\r\nX-Sum: 1\r\nX-B: 2\r\n\r\n", body: "abc",
			trailers: Headers{{"X-Sum", "1"}, {"X-B", "2"}}},
		{name: "empty body", raw: "0\r\n\r\n", body: "", trailers: Headers{}},
		{name: "bad hex", raw: "zz\r\nabc\r\n0\r\n\r\n", err: ErrChunkSize},
		{name: "empty size", raw: "\r\nabc\r\n", err: ErrChunkSize},
		{name: "size overflow", raw: "ffffffffffffffffff\r\n", err: ErrChunkSize},
		{name: "negative", raw: "-1\r\n", err: ErrChunkSize},
		{name: "missing CRLF after data", raw: "3\r\nabcX\r\n0\r\n\r\n", err: ErrChunkEnd},
		{name: "SPEC: bare LF on size line", raw: "3\nabc\r\n0\r\n\r\n", err: ErrBareLF},
		{name: "SPEC: obs-fold in trailer", raw: "0\r\nX: 1\r\n 2\r\n\r\n", err: ErrObsFold},
		{name: "SPEC: Content-Length in trailer", raw: "0\r\nContent-Length: 5\r\n\r\n", err: ErrForbiddenTrailer},
		{name: "SPEC: Transfer-Encoding in trailer", raw: "0\r\ntransfer-encoding: chunked\r\n\r\n", err: ErrForbiddenTrailer},
		{name: "SPEC: Host in trailer", raw: "3\r\nabc\r\n0\r\nX-Ok: 1\r\nHOST: evil\r\n\r\n", err: ErrForbiddenTrailer},
		{name: "truncated data", raw: "5\r\nhel", err: io.ErrUnexpectedEOF},
		{name: "truncated before last chunk", raw: "3\r\nabc\r\n", err: io.ErrUnexpectedEOF},
		// Found by FuzzReadRequestDifferential: EOF right after the last
		// chunk's size line used to surface as a clean io.EOF.
		{name: "truncated before trailer section", raw: "0\r\n", err: io.ErrUnexpectedEOF},
		{name: "truncated inside trailer section", raw: "0\r\nX-T: 1\r\n", err: io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := br(c.raw)
			cr := NewChunkedReader(r, DefaultLimits)
			b, err := io.ReadAll(cr)
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("err = %v, want %v", err, c.err)
				}
				return
			}
			if err != nil || string(b) != c.body {
				t.Fatalf("body = %q, %v", b, err)
			}
			if len(cr.Trailers()) != len(c.trailers) {
				t.Fatalf("trailers = %v", cr.Trailers())
			}
			for i := range c.trailers {
				if cr.Trailers()[i] != c.trailers[i] {
					t.Fatalf("trailers = %v", cr.Trailers())
				}
			}
			rest, _ := io.ReadAll(r)
			if string(rest) != c.rest {
				t.Fatalf("rest = %q", rest)
			}
		})
	}
}

// Streaming: one byte per underlying Read still decodes, proving the reader
// never needs the whole body up front.
func TestChunkedReader_Streaming(t *testing.T) {
	raw := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	r := bufioOver(iotest.OneByteReader(strings.NewReader(raw)))
	b, err := io.ReadAll(NewChunkedReader(r, DefaultLimits))
	if err != nil || string(b) != "hello world" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestChunkedReader_TrailerLimit(t *testing.T) {
	lim := Limits{MaxStartLine: 64, MaxHeaderCount: 1, MaxHeaderBytes: 1024}
	_, err := io.ReadAll(NewChunkedReader(br("0\r\nA: 1\r\nB: 2\r\n\r\n"), lim))
	if !errors.Is(err, ErrTooManyHeader) {
		t.Fatalf("err = %v", err)
	}
}

func TestFixedReader(t *testing.T) {
	r := br("helloREST")
	b, err := io.ReadAll(bodyReader(r, Framing{Kind: FramingContentLength, Length: 5}, DefaultLimits))
	if err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "REST" {
		t.Fatalf("rest = %q", rest)
	}
	_, err = io.ReadAll(bodyReader(br("hel"), Framing{Kind: FramingContentLength, Length: 5}, DefaultLimits))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated err = %v", err)
	}
}

func TestHelpers(t *testing.T) {
	h := Headers{{"Transfer-Encoding", "gzip, Chunked"}, {"transfer-encoding", " identity ;q=1"}}
	got, err := transferCodings(h)
	if err != nil || strings.Join(got, ",") != "gzip,chunked,identity" {
		t.Fatalf("transferCodings = %q", got)
	}
	if n, err := parseContentLength([]string{"7", "7, 7"}); err != nil || n != 7 {
		t.Fatalf("CL = %d %v", n, err)
	}
	if _, err := parseContentLength([]string{"7", "8"}); !errors.Is(err, ErrConflictingCL) {
		t.Fatalf("err = %v", err)
	}
	if _, err := parseContentLength([]string{"+7"}); !errors.Is(err, ErrInvalidCL) {
		t.Fatalf("err = %v", err)
	}
	if !h.Has("TRANSFER-ENCODING") || h.Has("Content-Length") || h.Get("transfer-encoding") != "gzip, Chunked" {
		t.Fatal("Has/Get")
	}
}

func bufioOver(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 16) }
