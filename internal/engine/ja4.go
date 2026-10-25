package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// ja4 computes FoxIO's TLS client fingerprint (the "ja4" part of JA4+), computed
// from the ClientHello. It describes *how a TLS stack says hello*, not who
// the user is: every copy of the same browser build produces the same
// value, and a Python script claiming to be Chrome in its User-Agent does
// not. That mismatch is the defender's signal. Spec:
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//
// Format: a_b_c, for example t13d1516h2_8daaf6152771_e5627efa2ab1
//
//	a (readable, 10 chars):
//	  t          transport: t = TCP (q = QUIC, d = DTLS; Sluice only sees TCP)
//	  13         highest TLS version offered (supported_versions, else legacy_version)
//	  d          d = SNI present (a domain), i = no SNI (an IP)
//	  15         number of cipher suites, 2 digits, GREASE excluded, max 99
//	  16         number of extensions, 2 digits, GREASE excluded, max 99
//	  h2         first and last character of the first ALPN value, 00 if none
//	b: first 12 hex chars of SHA-256 over the cipher suites, as 4-digit
//	   lowercase hex, GREASE removed, *sorted*, comma-joined
//	c: first 12 hex chars of SHA-256 over the extension types (sorted, GREASE,
//	   SNI and ALPN removed) + "_" + signature algorithms in wire order
//
// Sorting is the key design choice: Chrome shuffles its extension order on
// every connection (to stop servers ossifying on it), which made the older
// JA3 hash change constantly. Sorted lists keep JA4 stable.
func ja4(h *clientHello) string {
	ciphers := withoutGREASE(h.CipherSuites)
	exts := withoutGREASE(h.Extensions)

	sni := "i"
	if slices.Contains(h.Extensions, extServerName) {
		sni = "d"
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(h), sni, min(len(ciphers), 99), min(len(exts), 99), ja4ALPN(h.ALPN))

	// SNI and ALPN are left out of c: they are already in a, and SNI's
	// presence depends on the target (IP or name), not on the client.
	var cExts []uint16
	for _, e := range exts {
		if e != extServerName && e != extALPN {
			cExts = append(cExts, e)
		}
	}
	slices.Sort(ciphers)
	slices.Sort(cExts)

	c := ja4Hash("")
	if len(cExts) > 0 {
		in := hexList(cExts)
		if sigs := withoutGREASE(h.SignatureAlgorithms); len(sigs) > 0 {
			in += "_" + hexList(sigs) // not sorted: the order is part of the stack's identity
		}
		c = ja4Hash(in)
	}
	return a + "_" + ja4Hash(hexList(ciphers)) + "_" + c
}

// isGREASE reports whether v is a GREASE value (RFC 8701): 0x0a0a, 0x1a1a,
// ... 0xfafa. Clients sprinkle these random reserved values into their
// lists so servers learn to ignore unknown entries; they would make every
// fingerprint random, so JA4 drops them.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func withoutGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// ja4Version maps the highest offered version to its two-character code.
func ja4Version(h *clientHello) string {
	v := h.LegacyVersion
	if vs := withoutGREASE(h.SupportedVersions); len(vs) > 0 {
		v = slices.Max(vs)
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

// ja4ALPN is the first and last character of the first ALPN value ("h2" ->
// "h2", "http/1.1" -> "h1"). A value starting or ending in a byte that is
// not an ASCII letter or digit is shown as the first and last character of
// its hex form instead, so the fingerprint stays printable.
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	p := alpn[0]
	first, last := p[0], p[len(p)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	hx := hex.EncodeToString([]byte(p))
	return string([]byte{hx[0], hx[len(hx)-1]})
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func hexList(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// ja4Hash truncates SHA-256 to 12 hex characters. An empty input (no
// ciphers, or no extensions) is written as twelve zeros, per the spec.
func ja4Hash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
