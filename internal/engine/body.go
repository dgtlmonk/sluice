package engine

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// bodyReader wraps br according to the framing. Nothing is read ahead.
func bodyReader(br *bufio.Reader, f Framing, lim Limits) io.Reader {
	switch f.Kind {
	case FramingContentLength:
		return &fixedReader{r: br, n: f.Length}
	case FramingChunked:
		return NewChunkedReader(br, lim)
	case FramingCloseDelimited:
		return br
	}
	return strings.NewReader("")
}

// fixedReader is io.LimitReader that fails loudly: if the peer closes before
// n bytes arrive, the body was truncated and must not look complete.
type fixedReader struct {
	r io.Reader
	n int64
}

func (f *fixedReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > f.n {
		p = p[:f.n]
	}
	n, err := f.r.Read(p)
	f.n -= int64(n)
	if errors.Is(err, io.EOF) && f.n > 0 {
		return n, io.ErrUnexpectedEOF
	}
	if f.n == 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// ChunkedReader decodes a chunked body (RFC 9112 §7.1) as it arrives:
//
//	chunk      = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
//	last-chunk = 1*"0" [ chunk-ext ] CRLF
//	body       = *chunk last-chunk trailer-section CRLF
//
// chunk-size is hex. Extensions (";name=value") are allowed and ignored.
// Trailers are header fields after the last chunk; they are available from
// Trailers once Read has returned io.EOF.
type ChunkedReader struct {
	br       *bufio.Reader
	lim      Limits
	left     int64 // bytes remaining in the current chunk
	done     bool
	err      error
	trailers Headers
	// tap, if set, sees every raw byte the decoder consumes: size lines,
	// extensions, chunk data, CRLFs and trailers. Concatenated, the tap
	// output is the body exactly as it was on the wire.
	tap func([]byte)
}

// SetRawTap registers fn to receive the raw (still chunk-framed) bytes as
// they are consumed. fn must not retain the slice past the call.
func (c *ChunkedReader) SetRawTap(fn func([]byte)) { c.tap = fn }

func (c *ChunkedReader) emit(b []byte) {
	if c.tap != nil && len(b) > 0 {
		c.tap(b)
	}
}

// NewChunkedReader decodes from br. lim bounds chunk-size lines and trailers.
func NewChunkedReader(br *bufio.Reader, lim Limits) *ChunkedReader {
	return &ChunkedReader{br: br, lim: lim}
}

// Trailers returns the trailer fields; nil until the body has been read to EOF.
func (c *ChunkedReader) Trailers() Headers { return c.trailers }

func (c *ChunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.done {
		return 0, io.EOF
	}
	if c.left == 0 {
		if err := c.nextChunk(); err != nil {
			c.err = err
			return 0, err
		}
		if c.done {
			return 0, io.EOF
		}
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.br.Read(p)
	c.left -= int64(n)
	c.emit(p[:n])
	if errors.Is(err, io.EOF) {
		c.err = io.ErrUnexpectedEOF
		return n, c.err
	}
	if err != nil {
		c.err = err
		return n, err
	}
	if c.left == 0 {
		// Each chunk's data is followed by its own CRLF, strictly.
		if err := c.expectCRLF(); err != nil {
			c.err = err
			return n, err
		}
	}
	return n, nil
}

func (c *ChunkedReader) lineReader() *lineReader {
	return &lineReader{br: c.br, lim: c.lim}
}

// forbiddenTrailers are fields rejected inside a chunked trailer section.
var forbiddenTrailers = []string{"Content-Length", "Transfer-Encoding", "Host"}

// nextChunk reads a chunk-size line; on the last chunk it reads trailers.
func (c *ChunkedReader) nextChunk() error {
	sizeLR := c.lineReader()
	line, err := sizeLR.readLine(c.lim.MaxStartLine, ErrChunkSize)
	c.emit(sizeLR.raw)
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF // the body ended before its last chunk
	}
	if err != nil {
		return err
	}
	sizeStr, _, _ := strings.Cut(line, ";")
	// BWS before ';' is tolerated by RFC 9112 §7.1.1; strip trailing SP/HTAB.
	sizeStr = strings.TrimRight(sizeStr, " \t")
	size, err := parseHexSize(sizeStr)
	if err != nil {
		return err
	}
	if size > 0 {
		c.left = size
		return nil
	}
	// Trailers share the header-field grammar and limits.
	trLR := c.lineReader()
	tr, err := readFields(trLR)
	c.emit(trLR.raw)
	if errors.Is(err, io.EOF) {
		// "0\r\n" then close: the trailer section and its final CRLF never
		// arrived. readLine reports a clean io.EOF for a fresh line, and
		// passing that up would make a truncated body look complete.
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	// RFC 9110 §6.5.1: trailers must not carry fields needed for framing
	// or routing. If a later hop merged trailers into the head, a trailer
	// Content-Length / Transfer-Encoding / Host could re-frame or re-route a
	// message after it was already checked. Reject; and trailers are always
	// kept separate from Headers, never merged.
	for _, f := range tr {
		for _, bad := range forbiddenTrailers {
			if strings.EqualFold(f.Name, bad) {
				return ErrForbiddenTrailer
			}
		}
	}
	c.trailers = tr
	if c.trailers == nil {
		c.trailers = Headers{}
	}
	c.done = true
	return nil
}

// parseHexSize parses 1*HEXDIG with an explicit overflow guard: a huge size
// like "ffffffffffffffffff" must not wrap around to a small number, or two
// parsers would disagree on where the chunk ends.
func parseHexSize(s string) (int64, error) {
	if s == "" {
		return 0, ErrChunkSize
	}
	var n int64
	for i := 0; i < len(s); i++ {
		var d byte
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, ErrChunkSize
		}
		if n > (1<<62)>>4 { // next shift would exceed 2^62: reject as absurd
			return 0, ErrChunkSize
		}
		n = n<<4 | int64(d)
	}
	return n, nil
}

func (c *ChunkedReader) expectCRLF() error {
	var b [2]byte
	n, err := io.ReadFull(c.br, b[:])
	c.emit(b[:n])
	if err != nil {
		return io.ErrUnexpectedEOF
	}
	if b != [2]byte{'\r', '\n'} {
		return ErrChunkEnd
	}
	return nil
}
