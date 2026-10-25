package main

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dgtlmonk/sluice/internal/storage"
	"github.com/dgtlmonk/sluice/internal/synth"
)

// maxDetailBody caps how much of a stored body the detail pane receives in
// one bridge message; the store keeps the whole (capped) body.
const maxDetailBody = 256 << 10

// Body encodings in MessageView.BodyEncoding.
const (
	encodingText = "text" // valid UTF-8, control characters escaped
	encodingHex  = "hex"  // not UTF-8: offset / hex / ASCII dump
)

// HeaderField is one header line as received. Name and Value are already
// display-safe (control characters escaped), so the UI renders them as-is.
type HeaderField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Malformed marks a line with no colon (or an obs-fold continuation).
	// It is shown, not dropped: odd lines are exactly what a tester wants to see.
	Malformed bool `json:"malformed"`
}

// MessageView is one side of an exchange, prepared for the detail pane.
//
// Everything here is captured traffic: untrusted. The Go side turns bytes
// into display-safe text so the UI never has to reason about binary data;
// the UI still renders it only as plain text nodes, never as HTML.
type MessageView struct {
	Captured  bool          `json:"captured"`
	StartLine string        `json:"startLine"`
	Headers   []HeaderField `json:"headers"` // wire order, duplicates kept
	Head      string        `json:"head"`    // raw head, escaped
	Body      string        `json:"body"`    // first maxDetailBody bytes, escaped or hex-dumped
	// BodyEncoding is encodingText or encodingHex.
	BodyEncoding string `json:"bodyEncoding"`
	BodyBytes    int    `json:"bodyBytes"` // stored body length
	BodyShown    int    `json:"bodyShown"` // bytes of it in Body
	// BodyViewTruncated: the view shows fewer bytes than are stored.
	BodyViewTruncated bool `json:"bodyViewTruncated"`
	// BodyTruncated: the stored copy itself was cut at the storage cap
	// (the full body was still forwarded).
	BodyTruncated bool `json:"bodyTruncated"`
}

// ExchangeView is what ExchangeDetail returns. It never carries secrets of
// the app itself (no DB key); it does carry captured headers unredacted,
// because this is the user's own view of their own store.
type ExchangeView struct {
	ID         int64       `json:"id"`
	Request    MessageView `json:"request"`
	Response   MessageView `json:"response"`
	ProxyError string      `json:"proxyError"`
	Synthetic  bool        `json:"synthetic"`
}

func viewFromStored(ex storage.Exchange) ExchangeView {
	return ExchangeView{
		ID:         ex.ID,
		Request:    messageView(ex.Request),
		Response:   messageView(ex.Response),
		ProxyError: escapeText(ex.Err),
	}
}

// viewFromSynth splits synthetic raw text at the blank line into head and body.
func viewFromSynth(d synth.Detail) ExchangeView {
	split := func(raw string) *storage.Message {
		head, body, ok := strings.Cut(raw, "\r\n\r\n")
		if !ok {
			return &storage.Message{RawHeaders: []byte(raw)}
		}
		return &storage.Message{RawHeaders: []byte(head + "\r\n\r\n"), RawBody: []byte(body)}
	}
	return ExchangeView{ID: d.ID, Request: messageView(split(d.Request)), Response: messageView(split(d.Response)), Synthetic: true}
}

func messageView(m *storage.Message) MessageView {
	if m == nil {
		return MessageView{Headers: []HeaderField{}, BodyEncoding: encodingText}
	}
	start, fields := splitHead(m.RawHeaders)
	body := m.RawBody
	if len(body) > maxDetailBody {
		body = body[:maxDetailBody]
		// Don't cut a multi-byte character in half: that would make a
		// UTF-8 body look binary. Back up over at most 3 continuation bytes.
		for i := 0; i < utf8.UTFMax-1 && len(body) > 0 && !utf8.Valid(body); i++ {
			body = body[:len(body)-1]
		}
	}
	v := MessageView{
		Captured:          true,
		StartLine:         start,
		Headers:           fields,
		Head:              escapeText(string(m.RawHeaders)),
		BodyBytes:         len(m.RawBody),
		BodyShown:         len(body),
		BodyViewTruncated: len(body) < len(m.RawBody),
		BodyTruncated:     m.BodyTruncated,
	}
	if utf8.Valid(body) {
		v.Body, v.BodyEncoding = escapeText(string(body)), encodingText
	} else {
		v.Body, v.BodyEncoding = hexDump(body), encodingHex
	}
	return v
}

// splitHead turns a raw head into its start line and header fields, in wire
// order with duplicates kept. It is a lenient display split, not the
// engine's strict parser: the store may hold heads the engine rejected
// (that is often why someone is looking), and a viewer must show them
// rather than fail. Bare LF line ends are accepted for the same reason.
func splitHead(raw []byte) (start string, fields []HeaderField) {
	fields = []HeaderField{}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if i == 0 {
			start = escapeText(line)
			continue
		}
		if line == "" {
			break // end of head
		}
		// RFC 9112 §5.2: a line starting with SP/HTAB is an obsolete line
		// fold. Sluice's parser rejects it; here it is flagged, not merged.
		if line[0] == ' ' || line[0] == '\t' {
			fields = append(fields, HeaderField{Value: escapeText(line), Malformed: true})
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			fields = append(fields, HeaderField{Value: escapeText(line), Malformed: true})
			continue
		}
		// Value OWS is trimmed (RFC 9110 §5.5); the name is kept as sent,
		// including any whitespace before the colon, which is itself a
		// smuggling tell worth seeing.
		fields = append(fields, HeaderField{Name: escapeText(name), Value: escapeText(strings.Trim(value, " \t"))})
	}
	return start, fields
}

// escapeText makes s safe to show as plain text: tabs and line ends stay,
// CRLF becomes LF, and every other control character, invalid byte, or
// invisible formatting character becomes a visible escape. The point is
// that what you see is what was sent: a lone CR, a NUL, or a right-to-left
// override (U+202E, which can make "exe.txt" display as "txt.exe") cannot
// hide in the view.
func escapeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&sb, `\x%02x`, s[i]) // invalid UTF-8 byte
		case r == '\n' || r == '\t':
			sb.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&sb, `\x%02x`, r) // C0 controls, DEL (incl. a lone CR)
		case unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ':
			// C1 controls, bidi overrides, zero-width chars, line separators.
			fmt.Fprintf(&sb, `\u{%04x}`, r)
		default:
			sb.WriteRune(r)
		}
		i += size
	}
	return sb.String()
}

// hexDump renders b as the classic 16-bytes-per-line view:
// offset, hex bytes, and the printable-ASCII column ('.' for the rest).
func hexDump(b []byte) string {
	var sb bytes.Buffer
	for off := 0; off < len(b); off += 16 {
		row := b[off:min(off+16, len(b))]
		fmt.Fprintf(&sb, "%08x  ", off)
		for i := 0; i < 16; i++ {
			if i < len(row) {
				fmt.Fprintf(&sb, "%02x ", row[i])
			} else {
				sb.WriteString("   ")
			}
			if i == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for _, c := range row {
			if c >= 0x20 && c < 0x7f {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}
