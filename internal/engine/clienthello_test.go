package engine

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// helloSpec describes a ClientHello to craft byte by byte.
type helloSpec struct {
	legacy   uint16
	ciphers  []uint16
	exts     []rawExt // wire order
	noExts   bool     // omit the extensions block entirely
	sessionN int      // session id length
}

type rawExt struct {
	typ  uint16
	data []byte
}

func u16b(v int) []byte { return []byte{byte(v >> 8), byte(v)} } //nolint:gosec // G115: test builder, values < 2^16

func vec16(b []byte) []byte { return append(u16b(len(b)), b...) }

func vec8(b []byte) []byte { return append([]byte{byte(len(b))}, b...) } //nolint:gosec // G115: test builder, short vectors

func u16list(vs ...uint16) []byte {
	var b []byte
	for _, v := range vs {
		b = append(b, u16b(int(v))...)
	}
	return b
}

func sniExt(name string) rawExt {
	entry := append([]byte{0}, vec16([]byte(name))...)
	return rawExt{extServerName, vec16(entry)}
}

func alpnExt(protos ...string) rawExt {
	var list []byte
	for _, p := range protos {
		list = append(list, vec8([]byte(p))...)
	}
	return rawExt{extALPN, vec16(list)}
}

func versionsExt(vs ...uint16) rawExt { return rawExt{extSupportedVersions, vec8(u16list(vs...))} }

func sigAlgsExt(vs ...uint16) rawExt { return rawExt{extSignatureAlgs, vec16(u16list(vs...))} }

// body returns the ClientHello body (no handshake header).
func (s helloSpec) body() []byte {
	b := u16b(int(s.legacy))
	b = append(b, make([]byte, 32)...) // random
	b = append(b, vec8(make([]byte, s.sessionN))...)
	b = append(b, vec16(u16list(s.ciphers...))...)
	b = append(b, vec8([]byte{0})...) // null compression
	if s.noExts {
		return b
	}
	var exts []byte
	for _, e := range s.exts {
		exts = append(exts, u16b(int(e.typ))...)
		exts = append(exts, vec16(e.data)...)
	}
	return append(b, vec16(exts)...)
}

// handshake wraps a body in the 4-byte handshake header.
func handshake(body []byte) []byte {
	n := len(body)
	return append([]byte{handshakeClientHello, byte(n >> 16), byte(n >> 8), byte(n)}, body...) //nolint:gosec // G115: 24-bit length split into bytes
}

// records splits msg into TLS handshake records of at most size bytes.
func records(msg []byte, size int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := min(size, len(msg))
		out = append(out, recordTypeHandshake, 3, 1)
		out = append(out, u16b(n)...)
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func (s helloSpec) wire() []byte { return records(handshake(s.body()), 1<<14) }

func readHello(b []byte) ([]byte, *clientHello, error) {
	return readClientHello(bufio.NewReader(bytes.NewReader(b)))
}

func basicSpec() helloSpec {
	return helloSpec{
		legacy:  0x0303,
		ciphers: []uint16{0x1301, 0x1302},
		exts:    []rawExt{sniExt("example.com"), alpnExt("h2", "http/1.1"), versionsExt(0x0304, 0x0303), sigAlgsExt(0x0403)},
	}
}

func TestReadClientHelloParsesFields(t *testing.T) {
	wire := basicSpec().wire()
	// Bytes the client sent behind its hello must stay unread.
	br := bufio.NewReader(bytes.NewReader(append(append([]byte(nil), wire...), "NEXT"...)))
	raw, h, err := readClientHello(br)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, wire) {
		t.Fatal("raw is not the exact record bytes")
	}
	if rest, _ := io.ReadAll(br); string(rest) != "NEXT" {
		t.Fatalf("rest = %q", rest)
	}
	if h.ServerName != "example.com" || strings.Join(h.ALPN, ",") != "h2,http/1.1" || len(h.CipherSuites) != 2 ||
		len(h.SupportedVersions) != 2 || len(h.SignatureAlgorithms) != 1 || len(h.Extensions) != 4 {
		t.Fatalf("hello = %+v", h)
	}
	if h.onlyH2() {
		t.Fatal("h2+http/1.1 counted as h2-only")
	}
}

// A hello split across several records (large post-quantum key shares do
// this) is reassembled, and raw keeps every record.
func TestReadClientHelloAcrossRecords(t *testing.T) {
	wire := records(handshake(basicSpec().body()), 7)
	raw, h, err := readHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, wire) || h.ServerName != "example.com" {
		t.Fatalf("raw %d bytes, hello %+v", len(raw), h)
	}
}

func TestReadClientHelloWithoutExtensions(t *testing.T) {
	s := basicSpec()
	s.noExts = true
	_, h, err := readHello(s.wire())
	if err != nil {
		t.Fatal(err)
	}
	if h.ServerName != "" || h.Extensions != nil {
		t.Fatalf("hello = %+v", h)
	}
}

// Every rejection rule in the reader and parser has a case here.
func TestReadClientHelloRejects(t *testing.T) {
	body := basicSpec().body()
	withExts := func(exts ...rawExt) []byte {
		s := basicSpec()
		s.exts = exts
		return s.wire()
	}
	hugeHello := []byte{handshakeClientHello, 0x01, 0x00, 0x01} // 65537 bytes
	cases := map[string][]byte{
		"plain HTTP":           []byte("GET / HTTP/1.1\r\n\r\n"),
		"not a handshake":      {23, 3, 3, 0, 1, 0},
		"SSLv2 major":          {recordTypeHandshake, 2, 0, 0, 1, 0},
		"empty record":         {recordTypeHandshake, 3, 1, 0, 0},
		"oversized record":     append([]byte{recordTypeHandshake, 3, 1}, u16b(maxRecordFragment+1)...),
		"truncated record":     records(handshake(body), 1<<14)[:20],
		"not a ClientHello":    records(append([]byte{2, 0, 0, 1}, 0), 100),
		"hello too large":      records(hugeHello, 100),
		"trailing message":     records(append(handshake(body), 20, 0, 0, 0), 1<<14),
		"too short":            records(handshake(body[:10]), 1<<14),
		"session id > 32":      func() []byte { s := basicSpec(); s.sessionN = 33; return s.wire() }(),
		"no cipher suites":     func() []byte { s := basicSpec(); s.ciphers = nil; return s.wire() }(),
		"odd cipher length":    records(handshake(append(append(append(u16b(0x0303), make([]byte, 33)...), 0, 3, 0x13, 0x01, 0x13), 1, 0)), 1<<14),
		"duplicate extension":  withExts(sniExt("a.test"), sniExt("b.test")),
		"truncated extension":  records(handshake(append(append(append(append(u16b(0x0303), make([]byte, 33)...), vec16(u16list(0x1301))...), 1, 0), 0, 4, 0, 0, 0, 9)), 1<<14),
		"extension list slack": records(handshake(append(body, 0)), 1<<14),
		"two SNI host names":   withExts(rawExt{extServerName, vec16(append(append([]byte{0}, vec16([]byte("a"))...), append([]byte{0}, vec16([]byte("b"))...)...))}),
		"empty SNI name":       withExts(rawExt{extServerName, vec16(append([]byte{0}, vec16(nil)...))}),
		"SNI too long":         withExts(sniExt(strings.Repeat("a", 256))),
		"SNI slack":            withExts(rawExt{extServerName, append(sniExt("a").data, 0)}),
		"empty ALPN list":      withExts(rawExt{extALPN, vec16(nil)}),
		"empty ALPN name":      withExts(alpnExt("h2", "")),
		"odd versions":         withExts(rawExt{extSupportedVersions, vec8([]byte{3, 4, 3})}),
		"empty versions":       withExts(rawExt{extSupportedVersions, vec8(nil)}),
		"odd sigalgs":          withExts(rawExt{extSignatureAlgs, vec16([]byte{4, 3, 8})}),
		"empty sigalgs":        withExts(rawExt{extSignatureAlgs, vec16(nil)}),
	}
	for name, wire := range cases {
		if _, h, err := readHello(wire); err == nil {
			t.Errorf("%s: accepted, hello %+v", name, h)
		}
	}
}

func TestOnlyH2(t *testing.T) {
	for alpn, want := range map[string]bool{"": false, "h2": true, "h2,h2": true, "h2,http/1.1": false, "http/1.1": false} {
		h := &clientHello{}
		if alpn != "" {
			h.ALPN = strings.Split(alpn, ",")
		}
		if got := h.onlyH2(); got != want {
			t.Errorf("%q: onlyH2 = %v", alpn, got)
		}
	}
}

// captureGoHello runs a crypto/tls client against a pipe and returns the
// ClientHello it wrote: a real-world hello for the parser.
func captureGoHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		_ = tls.Client(a, cfg).Handshake()
		_ = a.Close()
	}()
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, _, err := readClientHello(bufio.NewReader(b))
	_ = b.Close()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadClientHelloFromCryptoTLS(t *testing.T) {
	raw := captureGoHello(t, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}})
	_, h, err := readHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.ServerName != "example.com" || h.ALPN[0] != "h2" {
		t.Fatalf("hello = %+v", h)
	}
	// Go's client: TLS 1.3, SNI, http/2 first. The rest varies by Go version.
	if fp := ja4(h); !strings.HasPrefix(fp, "t13d") || fp[8:10] != "h2" {
		t.Fatalf("JA4 = %s", fp)
	}
}

func FuzzReadClientHello(f *testing.F) {
	f.Add(basicSpec().wire())
	f.Add(records(handshake(basicSpec().body()), 3))
	f.Fuzz(func(t *testing.T, b []byte) {
		raw, h, err := readHello(b)
		if err != nil {
			return
		}
		if !bytes.HasPrefix(b, raw) || h == nil {
			t.Fatal("accepted hello without its raw bytes")
		}
		_ = ja4(h) // must not panic on anything the parser accepts
	})
}
