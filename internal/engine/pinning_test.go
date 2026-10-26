package engine

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/testorigin"
)

// helloCapture is a fake conn that records what a tls.Client writes and
// fails every read, so a handshake on it stops right after the ClientHello.
type helloCapture struct {
	net.Conn
	buf bytes.Buffer
}

func (h *helloCapture) Write(b []byte) (int, error)      { return h.buf.Write(b) }
func (h *helloCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (h *helloCapture) Close() error                     { return nil }
func (h *helloCapture) SetDeadline(time.Time) error      { return nil }
func (h *helloCapture) SetReadDeadline(time.Time) error  { return nil }
func (h *helloCapture) SetWriteDeadline(time.Time) error { return nil }

// tls12Hello returns a real ClientHello capped at TLS 1.2. In TLS 1.2 the
// client's flight before ChangeCipherSpec is plaintext, so a test can follow
// this hello with a hand-made alert record that Sluice will decode; in TLS
// 1.3 the alert would be encrypted under keys only a full client has.
func tls12Hello(t *testing.T) []byte {
	t.Helper()
	hc := &helloCapture{}
	// #nosec G402 -- test client: TLS 1.2 is needed for a plaintext alert.
	_ = tls.Client(hc, &tls.Config{ServerName: testorigin.TLSServerName, MaxVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}).Handshake()
	if hc.buf.Len() == 0 {
		t.Fatal("no ClientHello captured")
	}
	return hc.buf.Bytes()
}

// helloThenWaitForCert sends the hello and reads until Sluice's first
// flight (ServerHello, Certificate, ...) has arrived, so certSent is true.
func helloThenWaitForCert(t *testing.T, c net.Conn, hello []byte) {
	t.Helper()
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [5]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 22 {
		t.Fatalf("server flight: %v %x", err, hdr)
	}
	// Give the server time to flush the rest of its flight and start
	// waiting for our next record.
	time.Sleep(50 * time.Millisecond)
}

// alertRecord is one plaintext TLS alert record: content type 21, version
// 3.3, length 2, then level (2 = fatal, 1 = warning) and description.
func alertRecord(level, code byte) []byte {
	return []byte{21, 3, 3, 0, 2, level, code}
}

func trustedEnv(t *testing.T) *tunnelEnv {
	return startTestOriginEnv(t, func(c *Config) { c.CATrusted = func() bool { return true } })
}

// Each certificate-rejection alert, with the CA trusted, flags pinning.
func TestPinFlagOnCertificateRejectAlerts(t *testing.T) {
	hello := tls12Hello(t)
	for _, code := range certRejectAlerts {
		t.Run(code.Error(), func(t *testing.T) {
			e := trustedEnv(t)
			c := e.connect(t)
			helloThenWaitForCert(t, c, hello)
			_, _ = c.Write(alertRecord(2, byte(code)))
			ex := e.rec.wait(t)
			if !ex.PinSuspected || ex.Unused || ex.Scheme != "https" || !strings.Contains(ex.Err, "remote error") {
				t.Fatalf("exchange = %+v", ex)
			}
			if f := e.srv.LearnedHosts(); len(f) != 1 || f[0].Reason != TunnelPinned {
				t.Fatalf("learned = %+v", f)
			}
		})
	}
}

// The same rejection alert with the CA not trusted is "CA not installed".
func TestPinFlagNeedsTrustedCA(t *testing.T) {
	e := startTestOriginEnv(t, func(c *Config) { c.CATrusted = func() bool { return false } })
	c := e.connect(t)
	helloThenWaitForCert(t, c, tls12Hello(t))
	_, _ = c.Write(alertRecord(2, 48))
	if ex := e.rec.wait(t); ex.PinSuspected || ex.Unused || ex.Err == "" {
		t.Fatalf("exchange = %+v", ex)
	}
	if f := e.srv.LearnedHosts(); len(f) != 0 {
		t.Fatalf("learned = %+v", f)
	}
}

// Alerts that do not mean "your certificate" are failures, not pinning.
func TestNoPinFlagOnOtherAlerts(t *testing.T) {
	hello := tls12Hello(t)
	for _, code := range []tls.AlertError{40, 49, 51, 80} {
		t.Run(code.Error(), func(t *testing.T) {
			e := trustedEnv(t)
			c := e.connect(t)
			helloThenWaitForCert(t, c, hello)
			_, _ = c.Write(alertRecord(2, byte(code)))
			ex := e.rec.wait(t)
			if ex.PinSuspected || ex.Unused || !strings.Contains(ex.Err, "client TLS handshake") {
				t.Fatalf("exchange = %+v", ex)
			}
			if f := e.srv.LearnedHosts(); len(f) != 0 {
				t.Fatalf("learned = %+v", f)
			}
		})
	}
}

// The Brave repro: the client gets our certificate and closes silently
// (FIN), says close_notify, or resets. None of these flags pinning; the row
// is kept as an unused connection, with https and no failure.
func TestSilentCloseAfterCertIsUnusedNotPinned(t *testing.T) {
	hello := tls12Hello(t)
	cases := map[string]func(net.Conn){
		"eof":          func(c net.Conn) { _ = c.Close() },
		"close_notify": func(c net.Conn) { _, _ = c.Write(alertRecord(1, 0)); _ = c.Close() },
		"reset": func(c net.Conn) {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // close with RST instead of FIN
			}
			_ = c.Close()
		},
	}
	for name, closeIt := range cases {
		t.Run(name, func(t *testing.T) {
			e := trustedEnv(t)
			c := e.connect(t)
			helloThenWaitForCert(t, c, hello)
			closeIt(c)
			ex := e.rec.wait(t)
			if ex.PinSuspected || !ex.Unused || ex.Err != unusedNote || ex.Scheme != "https" || ex.Status != 0 || ex.JA4 == "" {
				t.Fatalf("exchange = %+v", ex)
			}
			if f := e.srv.LearnedHosts(); len(f) != 0 {
				t.Fatalf("learned = %+v", f)
			}
		})
	}
}

// A preconnect closed before its ClientHello is unused too, and still https
// because the CONNECT was to :443.
func TestCloseBeforeHelloIsUnused(t *testing.T) {
	e := trustedEnv(t)
	rc := dialProxy(t, e.proxy)
	rc.send("CONNECT " + testorigin.TLSServerName + ":443 HTTP/1.1\r\nHost: x\r\n\r\n")
	if line, err := rc.br.ReadString('\n'); err != nil || !strings.Contains(line, " 200 ") {
		t.Fatalf("CONNECT: %q %v", line, err)
	}
	_ = rc.conn.Close()
	ex := e.rec.wait(t)
	if !ex.Unused || ex.PinSuspected || ex.Scheme != "https" || ex.Err != unusedNote {
		t.Fatalf("exchange = %+v", ex)
	}
}

// A client that stalls mid-handshake is a timeout: an error, never a pin.
func TestHandshakeTimeoutIsNotPinned(t *testing.T) {
	e := startTestOriginEnv(t, func(c *Config) {
		c.CATrusted = func() bool { return true }
		c.HeadReadTimeout = 300 * time.Millisecond
	})
	c := e.connect(t)
	helloThenWaitForCert(t, c, tls12Hello(t))
	ex := e.rec.wait(t)
	_ = c.Close()
	if ex.PinSuspected || ex.Unused || !strings.Contains(ex.Err, "client TLS handshake") {
		t.Fatalf("exchange = %+v", ex)
	}
}

// A CONNECT to a non-443 port that never sent TLS stays http; one that sent
// a ClientHello is https on any port.
func TestConnectSchemeFollowsPortAndHello(t *testing.T) {
	e := trustedEnv(t) // origin listens on a random high port
	c := e.connect(t)
	_, _ = io.WriteString(c, "not tls at all\r\n\r\n")
	if ex := e.rec.wait(t); ex.Scheme != "http" || ex.Unused {
		t.Fatalf("non-TLS: %+v", ex)
	}
	c = e.connect(t)
	helloThenWaitForCert(t, c, tls12Hello(t))
	_ = c.Close()
	if ex := e.rec.wait(t); ex.Scheme != "https" {
		t.Fatalf("TLS on %s: %+v", e.origin, ex)
	}
}

func TestReceivedAlertShapes(t *testing.T) {
	op := &net.OpError{Op: "remote error", Err: errors.New(tls.AlertError(46).Error())}
	if a, ok := receivedAlert(fmt.Errorf("wrapped: %w", op)); !ok || a != 46 {
		t.Fatalf("OpError shape: %v %v", a, ok)
	}
	if a, ok := receivedAlert(fmt.Errorf("quic: %w", tls.AlertError(48))); !ok || a != 48 {
		t.Fatalf("AlertError shape: %v %v", a, ok)
	}
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, syscall.ECONNRESET, &net.OpError{Op: "read", Err: syscall.ECONNRESET}} {
		if _, ok := receivedAlert(err); ok || certRejectAlert(err) || !closedWithoutAlert(err) {
			t.Fatalf("%v: misread as an alert", err)
		}
	}
	if certRejectAlert(&net.OpError{Op: "remote error", Err: errors.New(tls.AlertError(51).Error())}) {
		t.Fatal("decrypt_error counted as a certificate rejection")
	}
}

// The OpenSSL repro: a TLS 1.3 client checks the certificate before it
// switches to encrypted records, so it sends unknown_ca in plaintext.
// crypto/tls reports that as "bad record MAC"; the sniffer recovers the
// alert, so pinning is still flagged.
func TestPinFlagOnPlaintextAlertInTLS13(t *testing.T) {
	hc := &helloCapture{}
	// #nosec G402 -- test client: only the ClientHello is used.
	_ = tls.Client(hc, &tls.Config{ServerName: testorigin.TLSServerName, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}).Handshake()
	e := trustedEnv(t)
	c := e.connect(t)
	helloThenWaitForCert(t, c, hc.buf.Bytes())
	_, _ = c.Write(alertRecord(2, 48))
	ex := e.rec.wait(t)
	if !ex.PinSuspected || ex.Unused || !strings.Contains(ex.Err, "bad record MAC") || !strings.Contains(ex.Err, "plaintext alert: tls: unknown certificate authority") {
		t.Fatalf("exchange = %+v", ex)
	}
	if f := e.srv.LearnedHosts(); len(f) != 1 || f[0].Reason != TunnelPinned {
		t.Fatalf("learned = %+v", f)
	}
}

// The sniffer follows record boundaries however the bytes are split, and
// ignores alerts longer than two bytes (encrypted TLS 1.2 alerts).
func TestAlertSnifferScan(t *testing.T) {
	stream := append(append([]byte{22, 3, 1, 0, 3, 1, 2, 3}, 21, 3, 3, 0, 4, 9, 9, 9, 9), alertRecord(2, 42)...)
	for split := 1; split <= len(stream); split++ {
		s := &alertSniffer{}
		for p := stream; len(p) > 0; {
			k := min(split, len(p))
			s.scan(p[:k])
			p = p[k:]
		}
		if code, ok := s.alert(); !ok || code != 42 {
			t.Fatalf("split %d: alert = %d, %v", split, code, ok)
		}
	}
	s := &alertSniffer{}
	s.scan([]byte{21, 3, 3, 0, 4, 2, 48, 0, 0})
	if _, ok := s.alert(); ok {
		t.Fatal("long alert record counted as plaintext")
	}
	s = &alertSniffer{}
	s.scan(alertRecord(1, 0)) // warning close_notify: not kept
	if _, ok := s.alert(); ok {
		t.Fatal("warning alert kept")
	}
	s.scan(alertRecord(2, 48))
	s.scan(alertRecord(1, 0)) // a later warning must not mask the fatal one
	if code, ok := s.alert(); !ok || code != 48 {
		t.Fatalf("alert = %d, %v", code, ok)
	}
}

// A plaintext rejection alert followed by a silent close is a close, not
// pinning: only a bad-record-MAC failure means the alert ended the handshake.
func TestNoPinFlagWhenPlaintextAlertDidNotEndHandshake(t *testing.T) {
	err := &net.OpError{Op: "read", Err: io.EOF}
	if isLocalBadRecordMAC(err) || isLocalBadRecordMAC(errors.New("local error: tls: bad record MAC")) {
		t.Fatal("non-OpError or EOF taken as bad record MAC")
	}
	if !isLocalBadRecordMAC(&net.OpError{Op: "local error", Err: errors.New(tls.AlertError(20).Error())}) {
		t.Fatal("bad record MAC not recognised")
	}
}
