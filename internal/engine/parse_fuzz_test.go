package engine

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

/*
Differential fuzzing: engine.ReadRequest vs net/http.ReadRequest.

net/http is the reference oracle here (tests only; never in the proxy path).
Both parsers get the same bytes. The outcomes are compared:

	both reject              -> fine
	both accept              -> method, target, proto, headers and body
	                            must match exactly (after normalizing
	                            net/http's canonical header keys and its
	                            special handling of Host / Transfer-Encoding)
	we reject, net/http OK   -> (a) allowed ONLY when the input really shows
	                            the property our error names (strictnessHolds)
	we accept, net/http no   -> (b) allowed ONLY for the documented looser
	                            rules below (looserHolds)

Intended divergences, (a) Sluice is stricter. Each one is a smuggling or
ambiguity guard from SPEC.md "HTTP/1.1"; the predicate re-derives the
property from the raw bytes, so a parser bug that rejects for the wrong
reason is still a failure:

	bare LF / bare CR line ends     ErrBareLF, ErrBareCR
	obs-fold continuation lines     ErrObsFold
	whitespace before the colon     ErrSpaceBeforeCol
	field name not a token ("A B")  ErrHeaderName (net/http keeps it verbatim)
	control bytes in a field value  ErrHeaderValue
	request line not exactly "token SP target SP HTTP/d.d" ErrRequestLine
	version other than 1.0 / 1.1    ErrUnsupportedV
	Host missing on 1.1, or repeated on any version  ErrHost
	Content-Length + TE together    ErrCLAndTE
	TE whose final coding is not chunked, or chunked twice, or empty list
	elements, or a coding name that is not a token
	                                ErrTENotChunked, ErrTEChunkedTwice, ErrTEEmptyElement, ErrTECoding
	TE on an HTTP/1.0 request       ErrTEOnHTTP10
	empty CL list elements, CL with signs / spaces ErrInvalidCL
	head limits (line length, field count, head bytes) ErrLineTooLong, ErrTooManyHeader, ErrHeaderTooBig
	chunked body: strict CRLF on size lines and after chunk data, bare LF/CR,
	size overflow, framing fields in trailers   ErrChunkSize, ErrChunkEnd, ErrForbiddenTrailer
	trailer field lines go through the same field grammar as the head.

Intended divergences, (b) Sluice is looser:

	request-target form. ReadRequest only checks the target has no CTL/SP
	bytes; the form (origin / absolute / authority / asterisk) is validated
	by the proxy layer (parseAbsoluteTarget in target.go), which is where the
	proxy decides how to route. net/http runs url.ParseRequestURI here.
	Content-Length "5, 5" (identical list repeats in ONE line): RFC 9110 §8.6
	lets a recipient accept them; net/http only collapses repeats across
	separate lines. Repeats are compared as numbers, so "05" and "5" agree
	(every hop reads the same length); net/http compares the strings.
	Transfer-Encoding "gzip, chunked": RFC 9112 §6.1 allows other codings
	before a final chunked. Sluice de-chunks and forwards the inner coding
	untouched; net/http only implements a bare "chunked".

Everything else is a bug in one of the parsers and fails the fuzz target.
*/

// maxFuzzBody bounds how much body either side reads, so a huge declared
// length cannot make one fuzz iteration allocate without limit.
const maxFuzzBody = 1 << 16

func FuzzReadRequestDifferential(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ours, oursBody, oursErr := readOurs(data)
		theirs, theirsBody, theirsErr := readTheirs(data)

		switch {
		case oursErr != nil && theirsErr != nil:
			return
		case oursErr != nil:
			if !strictnessHolds(oursErr, data) {
				t.Fatalf("(a) unexplained rejection: ours=%v, net/http accepts\ninput=%q", oursErr, data)
			}
		case theirsErr != nil:
			if !looserHolds(theirsErr, ours, data) {
				t.Fatalf("(b) we accept, net/http rejects: %v\ninput=%q", theirsErr, data)
			}
		default:
			if diff := compareParse(ours, oursBody, theirs, theirsBody); diff != "" {
				t.Fatalf("(c) parse mismatch: %s\ninput=%q", diff, data)
			}
		}
	})
}

// readOurs runs the engine parser and drains the body (bounded).
func readOurs(data []byte) (*Request, []byte, error) {
	req, err := ReadRequest(bufio.NewReader(bytes.NewReader(data)), DefaultLimits)
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxFuzzBody))
	if err != nil {
		return nil, nil, err
	}
	return req, body, nil
}

// readTheirs runs net/http and drains the body (bounded).
func readTheirs(data []byte) (*http.Request, []byte, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = req.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(req.Body, maxFuzzBody))
	if err != nil {
		return nil, nil, err
	}
	return req, body, nil
}

// compareParse returns "" when both parsers agree, else what differs.
func compareParse(o *Request, ob []byte, h *http.Request, hb []byte) string {
	switch {
	case o.Method != h.Method:
		return "method " + o.Method + " vs " + h.Method
	case o.Target != h.RequestURI:
		return "target " + o.Target + " vs " + h.RequestURI
	case o.Proto != h.Proto:
		return "proto " + o.Proto + " vs " + h.Proto
	case !bytes.Equal(ob, hb):
		return "body differs"
	}
	// net/http moves Host into req.Host and strips Transfer-Encoding into
	// req.TransferEncoding once chunked is applied; mirror that.
	want := map[string][]string{}
	for _, f := range o.Headers {
		k := textproto.CanonicalMIMEHeaderKey(f.Name)
		if k == "Host" || k == "Transfer-Encoding" {
			continue
		}
		want[k] = append(want[k], f.Value)
	}
	// net/http collapses identical repeated Content-Length lines into one.
	if cl := want["Content-Length"]; len(cl) > 1 {
		want["Content-Length"] = slices.Compact(cl)
	}
	got := map[string][]string{}
	for k, v := range h.Header {
		if k == "Transfer-Encoding" {
			continue
		}
		got[k] = v
	}
	if len(want) != len(got) {
		return "header key count differs"
	}
	for k, v := range want {
		if !slices.Equal(v, got[k]) {
			return "header " + k + " differs"
		}
	}
	if host := o.Headers.Get("Host"); o.Headers.Has("Host") && h.URL.Host == "" && host != h.Host {
		return "host " + host + " vs " + h.Host
	}
	return ""
}

// rawLines splits the head the way a lenient reader would (on LF, then
// dropping one trailing CR) up to the first empty line. Predicates run on
// these, independently of our parser, so they cannot share its bugs.
func rawLines(data []byte) (lines []string, head []byte, rest []byte) {
	off := 0
	for off < len(data) {
		i := bytes.IndexByte(data[off:], '\n')
		if i < 0 {
			return lines, data, nil
		}
		line := strings.TrimSuffix(string(data[off:off+i]), "\r")
		off += i + 1
		if line == "" && len(lines) > 0 {
			return lines, data[:off], data[off:]
		}
		lines = append(lines, line)
	}
	return lines, data, nil
}

// field is one header line split loosely: name before the first colon.
type field struct{ name, value string }

func rawFields(lines []string) []field {
	var fs []field
	for _, l := range lines[min(1, len(lines)):] {
		n, v, _ := strings.Cut(l, ":")
		fs = append(fs, field{name: n, value: strings.Trim(v, " \t")})
	}
	return fs
}

func rawValues(fs []field, name string) []string {
	var out []string
	for _, f := range fs {
		if strings.EqualFold(strings.TrimRight(f.name, " \t"), name) {
			out = append(out, f.value)
		}
	}
	return out
}

func hasBareLF(b []byte) bool {
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			return true
		}
	}
	return false
}

func hasBareCR(b []byte) bool {
	for i, c := range b {
		if c == '\r' && (i+1 >= len(b) || b[i+1] != '\n') {
			return true
		}
	}
	return false
}

// strictnessHolds reports whether the input really has the property our
// rejection names, i.e. the divergence is one of the documented (a) rules.
func strictnessHolds(err error, data []byte) bool {
	lines, head, rest := rawLines(data)
	headFs := rawFields(lines)
	fs := slices.Clone(headFs)
	start := ""
	if len(lines) > 0 {
		start = lines[0]
	}
	te := rawValues(fs, "Transfer-Encoding")
	cl := rawValues(fs, "Content-Length")
	is10 := strings.HasSuffix(start, " HTTP/1.0")
	// Trailer fields share the field grammar, so field-level rules may fire
	// on lines after the head of a chunked body. Approximate the trailer as
	// every body line; the property must still be present in the bytes.
	if len(te) > 0 {
		for _, l := range strings.Split(string(rest), "\n") {
			if l = strings.TrimSuffix(l, "\r"); l != "" {
				fs = append(fs, rawFields([]string{"", l})...)
			}
		}
	}
	switch {
	case errors.Is(err, ErrBareLF):
		return hasBareLF(data)
	case errors.Is(err, ErrBareCR):
		return hasBareCR(data)
	case errors.Is(err, ErrObsFold):
		return slices.ContainsFunc(fs, func(f field) bool { return f.name != "" && (f.name[0] == ' ' || f.name[0] == '\t') })
	case errors.Is(err, ErrSpaceBeforeCol):
		return slices.ContainsFunc(fs, func(f field) bool { return strings.TrimRight(f.name, " \t") != f.name })
	case errors.Is(err, ErrHeaderName):
		// net/http keeps non-token names (e.g. "A B: v") as-is.
		return slices.ContainsFunc(fs, func(f field) bool { return !isToken(f.name) })
	case errors.Is(err, ErrHeaderValue):
		return slices.ContainsFunc(fs, func(f field) bool {
			return strings.ContainsFunc(f.value, func(r rune) bool { return (r < 0x20 && r != '\t') || r == 0x7f })
		})
	case errors.Is(err, ErrRequestLine):
		return !strictRequestLine(start)
	case errors.Is(err, ErrUnsupportedV):
		return !is10 && !strings.HasSuffix(start, " HTTP/1.1")
	case errors.Is(err, ErrHost):
		hosts := len(rawValues(headFs, "Host"))
		return hosts > 1 || (!is10 && hosts == 0)
	case errors.Is(err, ErrCLAndTE):
		return len(te) > 0 && len(cl) > 0
	case errors.Is(err, ErrTEOnHTTP10):
		return is10 && len(te) > 0
	case errors.Is(err, ErrTEEmptyElement):
		return slices.ContainsFunc(te, hasEmptyElement)
	case errors.Is(err, ErrTENotChunked):
		c := rawCodings(te)
		return len(c) == 0 || c[len(c)-1] != "chunked"
	case errors.Is(err, ErrTECoding):
		return slices.ContainsFunc(rawCodings(te), func(c string) bool { return c != "" && !isToken(c) })
	case errors.Is(err, ErrTEChunkedTwice):
		return countCoding(rawCodings(te), "chunked") > 1
	case errors.Is(err, ErrInvalidCL), errors.Is(err, ErrConflictingCL):
		return slices.ContainsFunc(cl, func(v string) bool { return hasEmptyElement(v) || strings.ContainsAny(v, "+- \t") })
	case errors.Is(err, ErrLineTooLong):
		return len(start) > DefaultLimits.MaxStartLine
	case errors.Is(err, ErrTooManyHeader):
		return len(headFs) > DefaultLimits.MaxHeaderCount || len(fs)-len(headFs) > DefaultLimits.MaxHeaderCount
	case errors.Is(err, ErrHeaderTooBig):
		return len(head) > DefaultLimits.MaxHeaderBytes
	case errors.Is(err, ErrChunkSize):
		return len(te) > 0 && scanChunked(rest) == chunkBadSize
	case errors.Is(err, ErrChunkEnd):
		return len(te) > 0 && scanChunked(rest) == chunkBadEnd
	case errors.Is(err, ErrForbiddenTrailer):
		return len(te) > 0 && scanChunked(rest) == chunkBadTrailer
	}
	return false
}

// strictRequestLine is RFC 9112 §3 with single SPs: token SP target SP HTTP/d.d.
func strictRequestLine(s string) bool {
	parts := strings.Split(s, " ")
	if len(parts) != 3 || !isToken(parts[0]) || parts[1] == "" {
		return false
	}
	if strings.ContainsFunc(parts[1], func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return false
	}
	v := parts[2]
	return len(v) == 8 && strings.HasPrefix(v, "HTTP/") && v[6] == '.' &&
		v[5] >= '0' && v[5] <= '9' && v[7] >= '0' && v[7] <= '9'
}

func hasEmptyElement(v string) bool {
	return slices.ContainsFunc(strings.Split(v, ","), func(e string) bool { return strings.TrimSpace(e) == "" })
}

// looserHolds reports whether a (b) divergence is one of the documented
// looser rules.
func looserHolds(theirsErr error, ours *Request, data []byte) bool {
	msg := theirsErr.Error()
	// Request-target form is checked later by the proxy (target.go).
	// net/http returns url.ParseRequestURI's *url.Error unwrapped.
	if _, ok := errors.AsType[*url.Error](theirsErr); ok {
		return true
	}
	lines, _, _ := rawLines(data)
	fs := rawFields(lines)
	// Numerically equal CL repeats ("5, 5", "05" + "5"), read from the raw
	// bytes rather than from our parse, so a parser bug cannot excuse itself.
	if strings.Contains(msg, "Content-Length") {
		return ours.Framing.Kind == FramingContentLength && equalDigitList(rawValues(fs, "Content-Length"))
	}
	// Codings before the final chunked ("gzip, chunked"); names must be tokens.
	if strings.Contains(msg, "transfer encoding") { // "unsupported ..." / "too many ..."
		return ours.Framing.Kind == FramingChunked && looserTEShape(rawValues(fs, "Transfer-Encoding"))
	}
	return false
}

// listItems splits every value on commas and trims OWS from each element.
func listItems(values []string) []string {
	var out []string
	for _, v := range values {
		for _, e := range strings.Split(v, ",") {
			out = append(out, strings.Trim(e, " \t"))
		}
	}
	return out
}

// rawCodings is the TE coding list across all lines: comma split, trimmed,
// parameters dropped, lowercased. Empty elements are kept as "".
func rawCodings(te []string) []string {
	items := listItems(te)
	for i, e := range items {
		name, _, _ := strings.Cut(e, ";")
		items[i] = strings.ToLower(strings.Trim(name, " \t"))
	}
	return items
}

func countCoding(codings []string, name string) int {
	n := 0
	for _, c := range codings {
		if c == name {
			n++
		}
	}
	return n
}

// equalDigitList: every CL element is a non-empty digit string and all are
// the same number (leading zeros ignored, so no integer overflow).
func equalDigitList(cl []string) bool {
	items := listItems(cl)
	if len(items) == 0 {
		return false
	}
	norm := func(s string) string {
		if t := strings.TrimLeft(s, "0"); t != "" {
			return t
		}
		return "0"
	}
	first := ""
	for i, e := range items {
		if e == "" || strings.ContainsFunc(e, func(r rune) bool { return r < '0' || r > '9' }) {
			return false
		}
		if i == 0 {
			first = norm(e)
		} else if norm(e) != first {
			return false
		}
	}
	return true
}

// looserTEShape: final coding is chunked, chunked appears once, and every
// other element's coding name is a token (parameters after ';' are not
// interpreted by either hop: Sluice forwards the inner codings untouched).
func looserTEShape(te []string) bool {
	items := listItems(te)
	if len(items) == 0 || !strings.EqualFold(items[len(items)-1], "chunked") {
		return false
	}
	for _, e := range items[:len(items)-1] {
		name, _, _ := strings.Cut(e, ";")
		if !isToken(strings.Trim(name, " \t")) || strings.EqualFold(e, "chunked") {
			return false
		}
	}
	return true
}

// chunkDefect is what an independent scan of a chunked body finds first.
type chunkDefect int

const (
	chunkClean      chunkDefect = iota // well-formed through the final CRLF
	chunkBadSize                       // size line: bad hex, empty, overflow, too long
	chunkBadEnd                        // chunk data not followed by CRLF
	chunkBadTrailer                    // framing/routing field in the trailer
	chunkOther                         // truncated, bare CR/LF, ... (other rules)
)

// scanChunked is a small reference scanner for RFC 9112 §7.1, written
// separately from ChunkedReader so the (a) excuses for body errors check
// the defect is really in the bytes.
func scanChunked(b []byte) chunkDefect {
	// nextLine returns the line before the next CRLF. tooLong reports a line
	// longer than max before any CR/LF; ok=false means bare CR/LF or EOF.
	nextLine := func(max int) (line string, tooLong, ok bool) {
		j := bytes.IndexAny(b, "\r\n")
		if j > max || (j < 0 && len(b) > max) {
			return "", true, false
		}
		if j < 0 || b[j] != '\r' || j+1 >= len(b) || b[j+1] != '\n' {
			return "", false, false
		}
		line = string(b[:j])
		b = b[j+2:]
		return line, false, true
	}
	for {
		line, tooLong, ok := nextLine(DefaultLimits.MaxStartLine)
		if tooLong {
			return chunkBadSize
		}
		if !ok {
			return chunkOther
		}
		sizeStr, _, _ := strings.Cut(line, ";")
		sizeStr = strings.TrimRight(sizeStr, " \t")
		size, err := strconv.ParseUint(sizeStr, 16, 64)
		// Sluice caps sizes just above 2^62 (see parseHexSize).
		if err != nil || size >= 1<<62+16 {
			return chunkBadSize
		}
		if size == 0 {
			break
		}
		if uint64(len(b)) < size {
			return chunkOther
		}
		b = b[size:]
		if len(b) < 2 {
			return chunkOther
		}
		if b[0] != '\r' || b[1] != '\n' {
			return chunkBadEnd
		}
		b = b[2:]
	}
	forbidden := false
	for {
		line, _, ok := nextLine(DefaultLimits.MaxHeaderBytes)
		if !ok {
			return chunkOther
		}
		if line == "" {
			break
		}
		name, _, _ := strings.Cut(line, ":")
		for _, bad := range []string{"Content-Length", "Transfer-Encoding", "Host"} {
			forbidden = forbidden || strings.EqualFold(name, bad)
		}
	}
	if forbidden {
		return chunkBadTrailer
	}
	return chunkClean
}

// fuzzSeeds: valid requests plus every rejection / smuggling case from the
// unit tests, so the fuzzer starts at the interesting boundaries.
var fuzzSeeds = []string{
	"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
	"GET http://h:5000/x HTTP/1.0\r\n\r\n",
	"POST /a?b=1 HTTP/1.1\r\nHost: x\r\nX-Dup: 1\r\nx-dup:  2 \r\n\r\nBODY",
	"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
	"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-T: 1\r\n\r\n",
	"GET / HTTP/1.1\nHost: x\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\n\n",
	"GET / HTTP/1.1\r\nHost: x\ry\r\n\r\n",
	"GET /\r HTTP/1.1\r\nHost: x\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n 2\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n\t2\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\n: v\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\nnocolon\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\nX(A): v\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\n\r\n",
	"GET  / HTTP/1.1\r\nHost: x\r\n\r\n",
	"GET / HTTP/2.0\r\nHost: x\r\n\r\n",
	"GET / HTTP/1.1\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\n",
	"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: ,chunked\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 50\r\n\r\nhello",
	"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello",
	"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5,\r\n\r\nhello",
	"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\nhello",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 5\r\n\r\n",
}
