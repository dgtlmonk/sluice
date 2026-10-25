package engine

import (
	"errors"
	"testing"
)

// These tests specify decideBodyFraming (RFC 9112 §6.3 + SPEC.md rejection
// list).
func TestDecideBodyFraming(t *testing.T) {
	type tc struct {
		name       string
		h          Headers
		isResponse bool
		want       Framing
		wantErr    error
	}
	hdr := func(kv ...string) Headers {
		var h Headers
		for i := 0; i+1 < len(kv); i += 2 {
			h = append(h, Header{Name: kv[i], Value: kv[i+1]})
		}
		return h
	}
	cl := func(n int64) Framing { return Framing{Kind: FramingContentLength, Length: n} }
	chunked := Framing{Kind: FramingChunked}

	cases := []tc{
		// Rule 5: neither header.
		{name: "request no headers -> none", h: hdr("Host", "a"), want: Framing{Kind: FramingNone}},
		{name: "response no headers -> close-delimited", h: hdr(), isResponse: true, want: Framing{Kind: FramingCloseDelimited}},

		// Rule 4: Content-Length.
		{name: "CL 5", h: hdr("Content-Length", "5"), want: cl(5)},
		{name: "CL 0", h: hdr("Content-Length", "0"), want: cl(0)},
		{name: "CL on response", h: hdr("Content-Length", "12"), isResponse: true, want: cl(12)},
		{name: "CL identical repeated lines", h: hdr("Content-Length", "5", "content-length", "5"), want: cl(5)},
		{name: "CL identical comma list", h: hdr("Content-Length", "5, 5"), want: cl(5)},
		{name: "SPEC: CL differing lines", h: hdr("Content-Length", "5", "Content-Length", "6"), wantErr: ErrConflictingCL},
		{name: "SPEC: CL differing comma list", h: hdr("Content-Length", "5, 50"), wantErr: ErrConflictingCL},
		{name: "SPEC: CL differing on response", h: hdr("Content-Length", "1", "Content-Length", "2"), isResponse: true, wantErr: ErrConflictingCL},
		{name: "CL negative", h: hdr("Content-Length", "-1"), wantErr: ErrInvalidCL},
		{name: "CL plus sign", h: hdr("Content-Length", "+5"), wantErr: ErrInvalidCL},
		{name: "CL hex", h: hdr("Content-Length", "0x10"), wantErr: ErrInvalidCL},
		{name: "CL empty", h: hdr("Content-Length", ""), wantErr: ErrInvalidCL},
		{name: "CL overflow", h: hdr("Content-Length", "99999999999999999999"), wantErr: ErrInvalidCL},

		// Rule 2: chunked final.
		{name: "TE chunked", h: hdr("Transfer-Encoding", "chunked"), want: chunked},
		{name: "TE chunked case-insensitive", h: hdr("Transfer-Encoding", "Chunked"), want: chunked},
		{name: "TE gzip, chunked", h: hdr("Transfer-Encoding", "gzip, chunked"), want: chunked},
		{name: "TE split across lines", h: hdr("Transfer-Encoding", "gzip", "Transfer-Encoding", "chunked"), want: chunked},
		{name: "TE chunked on response", h: hdr("Transfer-Encoding", "chunked"), isResponse: true, want: chunked},

		// Rule 3: TE not ending in chunked.
		{name: "SPEC: TE gzip only", h: hdr("Transfer-Encoding", "gzip"), wantErr: ErrTENotChunked},
		{name: "SPEC: TE chunked, gzip", h: hdr("Transfer-Encoding", "chunked, gzip"), wantErr: ErrTENotChunked},
		{name: "SPEC: TE chunked then identity line", h: hdr("Transfer-Encoding", "chunked", "Transfer-Encoding", "identity"), wantErr: ErrTENotChunked},
		{name: "SPEC: TE xchunked", h: hdr("Transfer-Encoding", "xchunked"), wantErr: ErrTENotChunked},
		{name: "SPEC: TE non-token coding before chunked", h: hdr("Transfer-Encoding", "\", chunked"), wantErr: ErrTECoding},
		{name: "SPEC: TE coding with space", h: hdr("Transfer-Encoding", "a b, chunked"), wantErr: ErrTECoding},
		{name: "SPEC: TE empty value", h: hdr("Transfer-Encoding", ""), wantErr: ErrTEEmptyElement},
		{name: "SPEC: TE leading empty element", h: hdr("Transfer-Encoding", ",chunked"), wantErr: ErrTEEmptyElement},
		{name: "SPEC: TE trailing empty element", h: hdr("Transfer-Encoding", "chunked,"), wantErr: ErrTEEmptyElement},
		{name: "SPEC: TE empty line before chunked", h: hdr("Transfer-Encoding", "", "Transfer-Encoding", "chunked"), wantErr: ErrTEEmptyElement},
		{name: "SPEC: TE chunked, chunked", h: hdr("Transfer-Encoding", "chunked, chunked"), wantErr: ErrTEChunkedTwice},
		{name: "SPEC: TE chunked twice across lines", h: hdr("Transfer-Encoding", "chunked", "Transfer-Encoding", "chunked"), wantErr: ErrTEChunkedTwice},
		{name: "SPEC: TE chunked, gzip, chunked", h: hdr("Transfer-Encoding", "chunked, gzip, chunked"), wantErr: ErrTEChunkedTwice},
		{name: "TE gzip, chunked ok", h: hdr("Transfer-Encoding", "gzip, chunked"), want: chunked},
		{name: "SPEC: CL trailing empty element", h: hdr("Content-Length", "5,"), wantErr: ErrInvalidCL},
		{name: "SPEC: CL leading empty element", h: hdr("Content-Length", ",5"), wantErr: ErrInvalidCL},
		{name: "SPEC: CL double comma", h: hdr("Content-Length", "5,,5"), wantErr: ErrInvalidCL},
		{name: "SPEC: CL empty value", h: hdr("Content-Length", ""), wantErr: ErrInvalidCL},
		{name: "SPEC: TE not chunked on response", h: hdr("Transfer-Encoding", "gzip"), isResponse: true, wantErr: ErrTENotChunked},

		// Rule 1: both present.
		{name: "SPEC: CL and TE", h: hdr("Content-Length", "5", "Transfer-Encoding", "chunked"), wantErr: ErrCLAndTE},
		{name: "SPEC: TE and CL reversed order", h: hdr("Transfer-Encoding", "chunked", "Content-Length", "5"), wantErr: ErrCLAndTE},
		{name: "SPEC: CL and TE on response", h: hdr("Content-Length", "5", "Transfer-Encoding", "chunked"), isResponse: true, wantErr: ErrCLAndTE},
		{name: "SPEC: CL and non-chunked TE", h: hdr("Content-Length", "5", "Transfer-Encoding", "gzip"), wantErr: ErrCLAndTE},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decideBodyFraming(c.h, c.isResponse)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != c.want {
				t.Fatalf("framing = %+v, want %+v", got, c.want)
			}
		})
	}
}
