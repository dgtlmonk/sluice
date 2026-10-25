package engine

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// A hand-written ClientHello reader. The bypass decision (SPEC.md, HTTPS)
// has to be made before Sluice answers the TLS handshake, so the first
// flight from the client is read here, inspected, and then replayed byte for
// byte either to crypto/tls (decrypt) or to the origin (raw tunnel).
//
// Wire layout (RFC 8446 §5.1 and §4.1.2; TLS 1.2 is the same shape):
//
//	TLS record:   type(1)=22 handshake | legacy_version(2) | length(2) | fragment
//	Handshake:    msg_type(1)=1 client_hello | length(3) | body
//	ClientHello:  legacy_version(2) | random(32) | session_id<0..32>
//	              cipher_suites<2..2^16-2> | compression_methods<1..2^8-1>
//	              extensions<8..2^16-1>    (absent only in ancient SSLv3 hellos)
//	Extension:    type(2) | length(2) | data
//
// A handshake message may be split over several records, so fragments are
// collected until the 4-byte handshake header's length is satisfied.

const (
	recordTypeHandshake   = 22
	handshakeClientHello  = 1
	maxRecordFragment     = 1<<14 + 256 // 2^14 plaintext, a little slack for odd stacks
	maxClientHello        = 1 << 16     // same cap as crypto/tls's maxHandshake
	extServerName         = 0x0000
	extSignatureAlgs      = 0x000d
	extALPN               = 0x0010
	extSupportedVersions  = 0x002b
	sniHostName           = 0
	maxSNIHostLen         = 255
	minClientHelloBodyLen = 2 + 32 + 1 + 2 + 2 + 1 // version, random, empty sid, one suite, one compression
)

// clientHello is the part of a ClientHello Sluice needs: the bypass
// decision (SNI, ALPN) and the JA4 fingerprint (everything else). Values are
// kept in wire order; GREASE values are kept too, JA4 drops them itself.
type clientHello struct {
	LegacyVersion       uint16
	CipherSuites        []uint16
	Extensions          []uint16 // extension types, wire order
	ServerName          string   // SNI host_name, "" when absent
	ALPN                []string // protocol names, client preference order
	SupportedVersions   []uint16 // from supported_versions (TLS 1.3 clients)
	SignatureAlgorithms []uint16 // from signature_algorithms, wire order
}

var errNotTLS = errors.New("not a TLS handshake record")

// readClientHello reads whole TLS records from br until one complete
// ClientHello handshake message has arrived. It returns the exact record
// bytes it consumed (to be replayed) and the parsed hello.
func readClientHello(br *bufio.Reader) (raw []byte, h *clientHello, err error) {
	var msg []byte // handshake message bytes, reassembled across records
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return nil, nil, fmt.Errorf("record header: %w", err)
		}
		// hdr[1] is the record's legacy version major: 3 for SSLv3 to TLS 1.3.
		if hdr[0] != recordTypeHandshake || hdr[1] != 3 {
			return nil, nil, errNotTLS
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > maxRecordFragment {
			return nil, nil, fmt.Errorf("record length %d", n)
		}
		frag := make([]byte, n)
		if _, err := io.ReadFull(br, frag); err != nil {
			return nil, nil, fmt.Errorf("record body: %w", err)
		}
		raw = append(raw, hdr[:]...)
		raw = append(raw, frag...)
		msg = append(msg, frag...)
		if len(msg) < 4 {
			continue
		}
		if msg[0] != handshakeClientHello {
			return nil, nil, fmt.Errorf("first handshake message is type %d, not ClientHello", msg[0])
		}
		want := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
		if want > maxClientHello {
			return nil, nil, fmt.Errorf("ClientHello of %d bytes is too large", want)
		}
		switch {
		case len(msg)-4 < want:
			continue // the hello continues in the next record
		case len(msg)-4 > want:
			// Another handshake message in the same flight would be a
			// protocol violation for a client (it must wait for ServerHello).
			return nil, nil, errors.New("trailing bytes after ClientHello")
		}
		h, err := parseClientHello(msg[4:])
		if err != nil {
			return nil, nil, err
		}
		return raw, h, nil
	}
}

// reader is a bounds-checked cursor over a byte slice. Every read that
// would run past the end sets ok=false and returns zero values, so parsing
// code can read field after field and check ok once per structure.
type reader struct {
	b  []byte
	ok bool
}

func newReader(b []byte) *reader { return &reader{b: b, ok: true} }

func (r *reader) bytes(n int) []byte {
	if !r.ok || n < 0 || n > len(r.b) {
		r.ok = false
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() int {
	v := r.bytes(1)
	if v == nil {
		return 0
	}
	return int(v[0])
}

func (r *reader) u16() uint16 {
	v := r.bytes(2)
	if v == nil {
		return 0
	}
	return uint16(v[0])<<8 | uint16(v[1])
}

// vec8 / vec16 read a length-prefixed vector (TLS "opaque x<..2^8-1>" and
// "<..2^16-1>") and return a reader over just its contents.
func (r *reader) vec8() *reader  { return newReader(r.bytes(r.u8())).inherit(r) }
func (r *reader) vec16() *reader { return newReader(r.bytes(int(r.u16()))).inherit(r) }

func (r *reader) inherit(parent *reader) *reader {
	if !parent.ok {
		r.ok = false
	}
	return r
}

func (r *reader) empty() bool { return len(r.b) == 0 }

func (r *reader) u16s() []uint16 {
	if len(r.b)%2 != 0 {
		r.ok = false
		return nil
	}
	out := make([]uint16, 0, len(r.b)/2)
	for !r.empty() && r.ok {
		out = append(out, r.u16())
	}
	return out
}

// parseClientHello parses a ClientHello body (after the 4-byte handshake
// header). It is strict: lengths must match exactly, extensions may not
// repeat (RFC 8446 §4.2), and no trailing bytes are allowed.
func parseClientHello(body []byte) (*clientHello, error) {
	if len(body) < minClientHelloBodyLen {
		return nil, errors.New("ClientHello too short")
	}
	r := newReader(body)
	h := &clientHello{LegacyVersion: r.u16()}
	r.bytes(32) // random
	if sid := r.vec8(); len(sid.b) > 32 {
		return nil, errors.New("session id longer than 32 bytes")
	}
	suites := r.vec16()
	if len(suites.b) == 0 {
		return nil, errors.New("no cipher suites")
	}
	h.CipherSuites = suites.u16s()
	if !suites.ok {
		return nil, errors.New("odd cipher suite list length")
	}
	if comp := r.vec8(); len(comp.b) == 0 {
		return nil, errors.New("no compression methods")
	}
	if !r.ok {
		return nil, errors.New("truncated ClientHello")
	}
	if r.empty() {
		return h, nil // no extensions block (SSLv3-era hello)
	}
	exts := r.vec16()
	if !r.ok || !r.empty() {
		return nil, errors.New("bad extensions length")
	}
	seen := map[uint16]bool{}
	for !exts.empty() {
		typ := exts.u16()
		data := exts.vec16()
		if !exts.ok {
			return nil, errors.New("truncated extension")
		}
		if seen[typ] {
			return nil, fmt.Errorf("duplicate extension 0x%04x", typ)
		}
		seen[typ] = true
		h.Extensions = append(h.Extensions, typ)
		if err := h.parseExtension(typ, data); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (h *clientHello) parseExtension(typ uint16, d *reader) error {
	switch typ {
	case extServerName:
		// server_name_list<1..2^16-1> of {name_type(1), host_name<1..2^16-1>}.
		// Only host_name (0) is defined; at most one per type.
		list := d.vec16()
		if !d.ok || !d.empty() || list.empty() {
			return errors.New("bad server_name extension")
		}
		for !list.empty() {
			nameType := list.u8()
			name := list.vec16()
			if !list.ok || name.empty() {
				return errors.New("bad server_name entry")
			}
			if nameType == sniHostName {
				if h.ServerName != "" {
					return errors.New("two SNI host names")
				}
				if len(name.b) > maxSNIHostLen {
					return errors.New("SNI host name too long")
				}
				h.ServerName = string(name.b)
			}
		}
	case extALPN:
		// protocol_name_list<2..2^16-1> of ProtocolName<1..2^8-1>.
		list := d.vec16()
		if !d.ok || !d.empty() || list.empty() {
			return errors.New("bad ALPN extension")
		}
		for !list.empty() {
			p := list.vec8()
			if !list.ok || p.empty() {
				return errors.New("bad ALPN protocol name")
			}
			h.ALPN = append(h.ALPN, string(p.b))
		}
	case extSupportedVersions:
		// In a ClientHello: versions<2..254> (1-byte length).
		list := d.vec8()
		if !d.ok || !d.empty() || list.empty() {
			return errors.New("bad supported_versions extension")
		}
		h.SupportedVersions = list.u16s()
		if !list.ok {
			return errors.New("bad supported_versions list")
		}
	case extSignatureAlgs:
		list := d.vec16()
		if !d.ok || !d.empty() || list.empty() {
			return errors.New("bad signature_algorithms extension")
		}
		h.SignatureAlgorithms = list.u16s()
		if !list.ok {
			return errors.New("bad signature_algorithms list")
		}
	}
	return nil
}

// onlyH2 reports whether the client offers HTTP/2 and nothing else. Such a
// client (gRPC, some mobile SDKs) cannot fall back to HTTP/1.1, so
// decrypting it would only break it; it is tunnelled raw until M8.
func (h *clientHello) onlyH2() bool {
	if len(h.ALPN) == 0 {
		return false
	}
	for _, p := range h.ALPN {
		if p != "h2" {
			return false
		}
	}
	return true
}
