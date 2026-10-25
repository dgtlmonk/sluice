package engine

import (
	"strconv"
	"strings"
)

// Header is one field line as received. Name keeps its original case so the
// raw view and replays stay byte-faithful; lookups are case-insensitive.
type Header struct {
	Name  string
	Value string
}

// Headers keeps field lines in arrival order. A map would lose order and
// merge duplicates, and duplicates are exactly what smuggling hides in.
type Headers []Header

// Values returns every value of the named field, in order (case-insensitive
// name match). Duplicated fields come back as separate entries.
func (h Headers) Values(name string) []string {
	var out []string
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			out = append(out, f.Value)
		}
	}
	return out
}

// Get returns the first value of the named field, or "".
func (h Headers) Get(name string) string {
	if v := h.Values(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// Has reports whether the named field appears at all (even with an empty value).
func (h Headers) Has(name string) bool { return len(h.Values(name)) > 0 }

// listElements splits comma-separated list values (RFC 9110 §5.6.1) across
// every field line, trimming OWS. So ["gzip, chunked"] and
// ["gzip", "chunked"] both give [gzip chunked].
//
// ok is false if any element is empty (",chunked", "5,", "5,,5", or an empty
// field value). RFC 9110 §5.6.1 tells recipients to *ignore* empty elements,
// but Sluice is strict on the framing fields: some hops drop empties, others
// treat them as errors or as a zero, and any such disagreement over where a
// body ends is a smuggling vector. Rejecting removes the ambiguity.
func listElements(values []string) (elems []string, ok bool) {
	for _, v := range values {
		for _, e := range strings.Split(v, ",") {
			e = strings.TrimSpace(e)
			if e == "" {
				return nil, false
			}
			elems = append(elems, e)
		}
	}
	return elems, true
}

// transferCodings returns the Transfer-Encoding codings, lowercased, in the
// order they were applied. The last one is the outermost encoding.
// An empty list element (or empty value) -> ErrTEEmptyElement; a coding
// name that is not a token -> ErrTECoding.
func transferCodings(h Headers) ([]string, error) {
	codings, ok := listElements(h.Values("Transfer-Encoding"))
	if !ok {
		return nil, ErrTEEmptyElement
	}
	for i, c := range codings {
		// Drop any parameters ("gzip;q=1" -> "gzip"); only the name matters here.
		name, _, _ := strings.Cut(c, ";")
		name = strings.TrimSpace(name)
		// RFC 9112 §7: transfer-coding = token. A non-token name ("\"",
		// "a b") is not a coding any hop can agree on; reject it rather than
		// let one hop ignore it and another refuse it.
		if !isToken(name) {
			return nil, ErrTECoding
		}
		codings[i] = strings.ToLower(name)
	}
	return codings, nil
}

// parseContentLength validates every Content-Length value and returns the
// single agreed length.
//
//   - each element must be 1*DIGIT (no sign, no spaces inside, no hex)
//   - "5, 5" or two "5" lines are allowed (RFC 9110 §8.6 lets a recipient
//     accept identical repeats) and collapse to 5
//   - any disagreement -> ErrConflictingCL; any bad element -> ErrInvalidCL
//   - an empty element ("5,", ",5", "5,,5", "") -> ErrInvalidCL (strict;
//     see listElements)
//
// values must be non-empty (the caller only asks when the field is present).
func parseContentLength(values []string) (int64, error) {
	elems, ok := listElements(values)
	if !ok || len(elems) == 0 {
		return 0, ErrInvalidCL
	}
	var n int64 = -1
	for _, e := range elems {
		v, err := parseDigits(e)
		if err != nil {
			return 0, err
		}
		if n >= 0 && v != n {
			return 0, ErrConflictingCL
		}
		n = v
	}
	return n, nil
}

// parseDigits accepts only ASCII digits. strconv.ParseInt alone would also
// take "+5" and "-0", which another parser in the chain might read differently.
func parseDigits(s string) (int64, error) {
	if s == "" || len(s) > 18 { // 18 digits always fits in int64.
		return 0, ErrInvalidCL
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrInvalidCL
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, ErrInvalidCL
	}
	return v, nil
}

// isTokenChar reports whether c is a tchar (RFC 9110 §5.6.2), the alphabet
// of field names and methods.
func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}
