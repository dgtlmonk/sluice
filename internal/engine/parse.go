package engine

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Limits caps what one message head may consume before it is rejected.
type Limits struct {
	MaxStartLine   int // request/status line bytes, CRLF excluded -> 400
	MaxHeaderCount int // field lines -> 431
	MaxHeaderBytes int // whole head (start line + fields + CRLFs) -> 431
}

// DefaultLimits mirror common server defaults (nginx: 8 KiB line, Go: 1 MiB
// head). They are generous enough for real browsers and small enough to stop
// a client from holding memory with an endless header section.
var DefaultLimits = Limits{MaxStartLine: 8 << 10, MaxHeaderCount: 100, MaxHeaderBytes: 64 << 10}

// Request is a parsed request head plus a streaming body.
type Request struct {
	Method  string
	Target  string // as sent: origin-form "/x", absolute-form "http://h/x", authority-form for CONNECT
	Proto   string // "HTTP/1.1"
	Major   int
	Minor   int
	Headers Headers
	// RawHead is the exact head bytes received, start line through the
	// blank line. Replay and the Raw view use it byte-for-byte.
	RawHead []byte
	Framing Framing
	// Body streams the decoded body; it is never buffered in full. Reading
	// it consumes the underlying connection, so it must be drained (or the
	// connection dropped) before the next message is read.
	Body io.Reader
}

// Response is a parsed response head plus a streaming body.
type Response struct {
	Proto      string
	Major      int
	Minor      int
	StatusCode int
	Reason     string
	Headers    Headers
	RawHead    []byte
	Framing    Framing
	Body       io.Reader
}

// head is what both message kinds share after the start line.
type head struct {
	startLine string
	headers   Headers
	raw       []byte
}

// lineReader reads CRLF-terminated lines while counting the bytes and
// field lines of one head against Limits.
type lineReader struct {
	br    *bufio.Reader
	lim   Limits
	raw   []byte // every byte consumed, for RawHead
	total int
}

// readLine returns one line without its CRLF. RFC 9112 §2.2 lets a recipient
// accept a bare LF as a line end, and §2.2 also says a bare CR may be
// rejected. Sluice rejects both: if this proxy accepted "\n" but the origin
// did not (or the reverse), the two would split lines differently and that
// mismatch is a smuggling primitive.
//
// max bounds the line length; tooLong is the error returned past it.
func (lr *lineReader) readLine(max int, tooLong error) (string, error) {
	var line []byte
	for {
		c, err := lr.br.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && (len(line) > 0 || len(lr.raw) > 0) {
				return "", io.ErrUnexpectedEOF
			}
			return "", err
		}
		lr.raw = append(lr.raw, c)
		lr.total++
		if lr.total > lr.lim.MaxHeaderBytes {
			return "", ErrHeaderTooBig
		}
		switch c {
		case '\n':
			return "", ErrBareLF // a proper LF is consumed in the '\r' case
		case '\r':
			next, err := lr.br.ReadByte()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return "", io.ErrUnexpectedEOF
				}
				return "", err
			}
			lr.raw = append(lr.raw, next)
			lr.total++
			if next != '\n' {
				return "", ErrBareCR
			}
			return string(line), nil
		}
		line = append(line, c)
		if len(line) > max {
			return "", tooLong
		}
	}
}

// readHead reads the start line and field lines up to the empty line.
func readHead(br *bufio.Reader, lim Limits) (*head, error) {
	lr := &lineReader{br: br, lim: lim}
	start, err := lr.readLine(lim.MaxStartLine, ErrLineTooLong)
	if err != nil {
		return nil, err
	}
	hs, err := readFields(lr)
	if err != nil {
		return nil, err
	}
	return &head{startLine: start, headers: hs, raw: lr.raw}, nil
}

// readFields parses field lines until the blank line (also used for trailers).
func readFields(lr *lineReader) (Headers, error) {
	var hs Headers
	for {
		line, err := lr.readLine(lr.lim.MaxHeaderBytes, ErrHeaderTooBig)
		if err != nil {
			return nil, err
		}
		if line == "" {
			return hs, nil
		}
		if len(hs) >= lr.lim.MaxHeaderCount {
			return nil, ErrTooManyHeader
		}
		f, err := parseField(line)
		if err != nil {
			return nil, err
		}
		hs = append(hs, f)
	}
}

// parseField splits "Name: value". RFC 9112 §5:
//   - a line starting with SP/HTAB is obs-fold (a continuation of the
//     previous line). It is obsolete and parsers disagree on it, so reject.
//   - no whitespace is allowed between the name and the colon (§5.1 MUST
//     reject with 400): "Transfer-Encoding : chunked" is a known smuggling
//     trick that some hops ignore and others honour.
//   - the value has leading/trailing OWS trimmed; NUL and other control
//     bytes (except HTAB) are rejected.
func parseField(line string) (Header, error) {
	if line[0] == ' ' || line[0] == '\t' {
		return Header{}, ErrObsFold
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok || name == "" {
		return Header{}, ErrHeaderName
	}
	if last := name[len(name)-1]; last == ' ' || last == '\t' {
		return Header{}, ErrSpaceBeforeCol
	}
	if !isToken(name) {
		return Header{}, ErrHeaderName
	}
	value = strings.Trim(value, " \t")
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return Header{}, ErrHeaderValue
		}
	}
	return Header{Name: name, Value: value}, nil
}

// parseVersion accepts exactly "HTTP/1.0" or "HTTP/1.1". Other well-formed
// versions get 505; anything else is malformed.
func parseVersion(s string, malformed error) (major, minor int, err error) {
	if len(s) != 8 || !strings.HasPrefix(s, "HTTP/") || s[6] != '.' ||
		s[5] < '0' || s[5] > '9' || s[7] < '0' || s[7] > '9' {
		return 0, 0, malformed
	}
	major, minor = int(s[5]-'0'), int(s[7]-'0')
	if major != 1 || minor > 1 {
		return 0, 0, ErrUnsupportedV
	}
	return major, minor, nil
}

// readRequestHead parses everything up to the body, without deciding framing.
func readRequestHead(br *bufio.Reader, lim Limits) (*Request, error) {
	h, err := readHead(br, lim)
	if err != nil {
		return nil, err
	}
	// request-line = method SP request-target SP HTTP-version, single SPs
	// only (RFC 9112 §3). Splitting on exactly one space means "GET  / HTTP/1.1"
	// yields an empty target and is rejected.
	parts := strings.Split(h.startLine, " ")
	if len(parts) != 3 || !isToken(parts[0]) || parts[1] == "" {
		return nil, ErrRequestLine
	}
	for i := 0; i < len(parts[1]); i++ {
		if c := parts[1][i]; c <= 0x20 || c == 0x7f {
			return nil, ErrRequestLine
		}
	}
	major, minor, err := parseVersion(parts[2], ErrRequestLine)
	if err != nil {
		return nil, err
	}
	// RFC 9112 §3.2: an HTTP/1.1 request MUST carry a Host, and a request
	// of ANY version with more than one Host line MUST be rejected: two hops
	// picking different Hosts would route the same bytes to different sites.
	hosts := len(h.headers.Values("Host"))
	if hosts > 1 || (minor == 1 && hosts == 0) {
		return nil, ErrHost
	}
	return &Request{
		Method: parts[0], Target: parts[1], Proto: parts[2], Major: major, Minor: minor,
		Headers: h.headers, RawHead: h.raw,
	}, nil
}

// ReadRequest reads one request. Body is a streaming reader over br.
func ReadRequest(br *bufio.Reader, lim Limits) (*Request, error) {
	req, err := readRequestHead(br, lim)
	if err != nil {
		return nil, err
	}
	// RFC 9112 §6.1: Transfer-Encoding was added in HTTP/1.1, so a 1.0
	// request carrying it must be treated as faulty framing. A 1.0 hop may
	// ignore TE entirely and read the chunked bytes as the next request.
	if req.Minor == 0 && req.Headers.Has("Transfer-Encoding") {
		return nil, ErrTEOnHTTP10
	}
	req.Framing, err = decideBodyFraming(req.Headers, false)
	if err != nil {
		return nil, err
	}
	req.Body = bodyReader(br, req.Framing, lim)
	return req, nil
}

// readResponseHead parses the status line and fields.
func readResponseHead(br *bufio.Reader, lim Limits) (*Response, error) {
	h, err := readHead(br, lim)
	if err != nil {
		return nil, err
	}
	// status-line = HTTP-version SP status-code SP [ reason-phrase ].
	// Some servers drop the SP before an empty reason; accept that too.
	version, rest, _ := strings.Cut(h.startLine, " ")
	major, minor, err := parseVersion(version, ErrStatusLine)
	if err != nil {
		return nil, err
	}
	code, reason, _ := strings.Cut(rest, " ")
	if len(code) != 3 || code[0] < '1' || code[0] > '5' {
		return nil, ErrStatusLine
	}
	n, err := strconv.Atoi(code)
	if err != nil || strings.ContainsAny(code, "+-") {
		return nil, ErrStatusLine
	}
	return &Response{
		Proto: version, Major: major, Minor: minor, StatusCode: n, Reason: reason,
		Headers: h.headers, RawHead: h.raw,
	}, nil
}

// responseHasNoBody covers RFC 9112 §6.3 rules 1-2: whatever the headers
// say, these responses end at the blank line. A reply to HEAD may carry the
// Content-Length of the GET it describes, which must not be read as a body.
// A 2xx to CONNECT switches to a tunnel, so there is no HTTP body either.
func responseHasNoBody(requestMethod string, status int) bool {
	switch {
	case requestMethod == "HEAD":
		return true
	case status >= 100 && status < 200, status == 204, status == 304:
		return true
	case requestMethod == "CONNECT" && status >= 200 && status < 300:
		return true
	}
	return false
}

// ReadResponse reads one response to a request with method requestMethod.
// A 1xx is returned as-is (no body); the caller reads the final response next.
func ReadResponse(br *bufio.Reader, lim Limits, requestMethod string) (*Response, error) {
	resp, err := readResponseHead(br, lim)
	if err != nil {
		return nil, err
	}
	if responseHasNoBody(requestMethod, resp.StatusCode) {
		resp.Framing = Framing{Kind: FramingNone}
	} else if resp.Framing, err = decideBodyFraming(resp.Headers, true); err != nil {
		return nil, err
	}
	resp.Body = bodyReader(br, resp.Framing, lim)
	return resp, nil
}
