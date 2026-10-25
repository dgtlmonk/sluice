// Package engine is Sluice's headless proxy core: the hand-written HTTP/1.1
// parser lives here (no net/http in the proxy path; see CLAUDE.md).
package engine

import (
	"errors"
	"fmt"
)

// ParseError is a rejected message. Status is the HTTP status the proxy
// should answer with when the bad message came from the client: 400 for
// malformed or ambiguous framing, 431 for oversized headers, 505 for an
// unsupported version. For a bad upstream response the proxy answers 502
// instead, but the Status still says what class of problem it was.
type ParseError struct {
	Status int
	Reason string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("http parse: %d %s", e.Status, e.Reason)
}

// Is makes errors.Is match on Status+Reason, so tests and callers can compare
// against the sentinel values below even if they were wrapped.
func (e *ParseError) Is(target error) bool {
	var t *ParseError
	if !errors.As(target, &t) {
		return false
	}
	return t.Status == e.Status && t.Reason == e.Reason
}

func badRequest(reason string) *ParseError { return &ParseError{Status: 400, Reason: reason} }

// Sentinel errors. Each one is a distinct rejection rule with its own test.
var (
	// Line-level framing.
	ErrBareCR        = badRequest("bare CR")
	ErrBareLF        = badRequest("bare LF (line not terminated by CRLF)")
	ErrRequestLine   = badRequest("malformed request line")
	ErrStatusLine    = badRequest("malformed status line")
	ErrLineTooLong   = badRequest("request line too long")
	ErrUnsupportedV  = &ParseError{Status: 505, Reason: "unsupported HTTP version"}
	ErrHeaderTooBig  = &ParseError{Status: 431, Reason: "header section too large"}
	ErrTooManyHeader = &ParseError{Status: 431, Reason: "too many header fields"}

	// Header fields.
	ErrObsFold        = badRequest("obsolete line folding")
	ErrHeaderName     = badRequest("invalid header field name")
	ErrSpaceBeforeCol = badRequest("whitespace between field name and colon")
	ErrHeaderValue    = badRequest("invalid character in header field value")
	ErrHost           = badRequest("missing Host on HTTP/1.1, or more than one Host")

	// Body framing (decided by decideBodyFraming).
	ErrCLAndTE        = badRequest("both Content-Length and Transfer-Encoding present")
	ErrConflictingCL  = badRequest("multiple differing Content-Length values")
	ErrInvalidCL      = badRequest("invalid Content-Length value")
	ErrTENotChunked   = badRequest("Transfer-Encoding final coding is not chunked")
	ErrTEChunkedTwice = badRequest("Transfer-Encoding applies chunked more than once")
	ErrTEEmptyElement = badRequest("empty element in Transfer-Encoding list")
	ErrTECoding       = badRequest("Transfer-Encoding coding name is not a token")
	ErrTEOnHTTP10     = badRequest("Transfer-Encoding in an HTTP/1.0 request")

	// Trailer fields.
	ErrForbiddenTrailer = badRequest("framing or routing field in chunked trailer")

	// Chunked body.
	ErrChunkSize = badRequest("invalid chunk size line")
	ErrChunkEnd  = badRequest("chunk data not followed by CRLF")
)
