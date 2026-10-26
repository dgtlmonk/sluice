package engine

import (
	"crypto/tls"
	"errors"
	"net"
)

// alertSniffer watches the client's bytes during the TLS handshake and
// remembers the last plaintext alert record it sent.
//
// Why: in TLS 1.3 the client switches to encrypted records only after it has
// checked the server's Finished. OpenSSL-based clients (curl built on
// OpenSSL, Python, many CLIs) check the certificate first and, on failure,
// send their alert in plaintext: a record of type 21 holding two bytes. Go's
// server already expects encrypted records at that point, so crypto/tls
// fails with "bad record MAC" and the alert's meaning is lost. Browsers and
// Go clients send the alert encrypted, and crypto/tls decodes those itself.
//
// A record is "content type (1) | version (2) | length (2) | body". A
// plaintext alert is type 21 with length 2 (level, description). An
// encrypted alert in TLS 1.2 also has type 21 but carries an AEAD tag, so it
// is longer than 2 bytes; in TLS 1.3 encrypted records are all type 23.
type alertSniffer struct {
	net.Conn
	hdr  [5]byte
	nhdr int // header bytes seen for the current record
	body int // body bytes still to skip (or collect) for the current record
	buf  []byte
	last []byte // body of the most recent plaintext fatal alert, if any
	done bool   // handshake finished: stop watching, the tunnel is untouched
}

func (s *alertSniffer) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	if !s.done {
		s.scan(b[:n])
	}
	return n, err
}

// scan follows record boundaries across reads of any size.
func (s *alertSniffer) scan(p []byte) {
	for len(p) > 0 {
		if s.body == 0 {
			k := copy(s.hdr[s.nhdr:], p)
			s.nhdr += k
			p = p[k:]
			if s.nhdr < len(s.hdr) {
				return
			}
			s.nhdr = 0
			s.body = int(s.hdr[3])<<8 | int(s.hdr[4])
			s.buf = s.buf[:0]
			continue
		}
		k := min(s.body, len(p))
		if s.isPlainAlert() {
			s.buf = append(s.buf, p[:k]...)
		}
		s.body -= k
		p = p[k:]
		if s.body == 0 && s.isPlainAlert() && s.buf[0] == 2 {
			s.last = append(s.last[:0], s.buf...)
		}
	}
}

func (s *alertSniffer) isPlainAlert() bool {
	return s.hdr[0] == 21 && s.hdr[3] == 0 && s.hdr[4] == 2
}

// alert returns the description code of the last plaintext fatal alert seen.
// Warning-level alerts (close_notify, level 1) are not kept: crypto/tls
// already turns those into a clean EOF, and none of them rejects a
// certificate.
func (s *alertSniffer) alert() (code byte, ok bool) {
	if len(s.last) != 2 {
		return 0, false
	}
	return s.last[1], true
}

// isLocalBadRecordMAC reports whether crypto/tls failed because a record did
// not decrypt: the symptom of a plaintext alert arriving where an encrypted
// record was expected. Locally raised alerts come back as a *net.OpError with
// Op "local error".
func isLocalBadRecordMAC(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "local error" && op.Err != nil &&
		op.Err.Error() == tls.AlertError(20).Error()
}
