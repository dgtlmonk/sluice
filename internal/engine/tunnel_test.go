package engine

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/testorigin"
)

// tunnelEnv is a proxy with interception on, in front of one TLS origin.
type tunnelEnv struct {
	proxy       string
	srv         *Server
	origin      string
	originRoots *x509.CertPool // what a client needs to trust the real origin
	sluiceRoots *x509.CertPool // what a client needs to trust Sluice's leaves
	rec         *hookRecorder
}

func startTunnelEnv(t *testing.T, origin string, originRoots *x509.CertPool, mutate func(*Config)) *tunnelEnv {
	t.Helper()
	auth, sluiceRoots := testCA(t)
	rec := newHookRecorder()
	rec.done = make(chan Exchange, 16)
	cfg := rec.config()
	cfg.LeafCerts = auth
	cfg.UpstreamRootCAs = originRoots
	if mutate != nil {
		mutate(&cfg)
	}
	proxy, srv := startProxy(t, cfg)
	return &tunnelEnv{proxy: proxy, srv: srv, origin: origin, originRoots: originRoots, sluiceRoots: sluiceRoots, rec: rec}
}

func startTestOriginEnv(t *testing.T, mutate func(*Config)) *tunnelEnv {
	t.Helper()
	origin, roots, stop := testorigin.StartTLS()
	t.Cleanup(stop)
	return startTunnelEnv(t, origin, roots, mutate)
}

// connect sends CONNECT and returns the raw conn once the 200 is read.
func (e *tunnelEnv) connect(t *testing.T) net.Conn {
	t.Helper()
	rc := dialProxy(t, e.proxy)
	rc.send("CONNECT " + e.origin + " HTTP/1.1\r\nHost: " + e.origin + "\r\n\r\n")
	resp, err := http.ReadResponse(rc.br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || rc.br.Buffered() != 0 {
		t.Fatalf("CONNECT status %d, %d extra bytes", resp.StatusCode, rc.br.Buffered())
	}
	return rc.conn
}

// handshake runs a client TLS handshake through the tunnel.
func tlsHandshake(t *testing.T, c net.Conn, roots *x509.CertPool, alpn ...string) (*tls.Conn, error) {
	t.Helper()
	tc := tls.Client(c, &tls.Config{ServerName: testorigin.TLSServerName, RootCAs: roots, NextProtos: alpn})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	return tc, tc.Handshake()
}

// getThrough sends one GET over an established TLS conn and returns the body.
func getThrough(t *testing.T, tc *tls.Conn) string {
	t.Helper()
	_, _ = io.WriteString(tc, "GET "+testorigin.PathContentLength+" HTTP/1.1\r\nHost: "+testorigin.TLSServerName+"\r\nConnection: close\r\n\r\n")
	b, err := io.ReadAll(tc)
	if err != nil && !strings.Contains(err.Error(), "close_notify") {
		t.Fatal(err)
	}
	return string(b)
}

// expectRawTunnel asserts that the client reached the real origin through an
// undecrypted tunnel: only the origin's own CA can verify the handshake, so
// Sluice cannot have minted the certificate.
func (e *tunnelEnv) expectRawTunnel(t *testing.T, reason string, alpn ...string) Exchange {
	t.Helper()
	tc, err := tlsHandshake(t, e.connect(t), e.originRoots, alpn...)
	if err != nil {
		t.Fatalf("handshake with the real origin through the tunnel: %v", err)
	}
	if body := getThrough(t, tc); !strings.HasSuffix(body, testorigin.ContentLengthBody) {
		t.Fatalf("body %q", body)
	}
	_ = tc.Close()
	ex := e.rec.wait(t)
	if ex.Method != "CONNECT" || ex.Tunnel != reason || ex.Scheme != "https" || ex.Status != 200 || ex.Err != "" {
		t.Fatalf("exchange = %+v, want tunnel %q", ex, reason)
	}
	if !strings.HasPrefix(ex.JA4, "t13d") || ex.ReqBytes == 0 || ex.RespBytes == 0 {
		t.Fatalf("exchange JA4 %q, bytes %d/%d", ex.JA4, ex.ReqBytes, ex.RespBytes)
	}
	return ex
}

func TestTunnelBypassList(t *testing.T) {
	e := startTestOriginEnv(t, func(c *Config) { c.BypassHosts = []string{"*.com"} })
	e.expectRawTunnel(t, TunnelBypass, "h2", "http/1.1")

	// Changed live: with the list cleared, the next CONNECT is decrypted.
	if err := e.srv.SetBypassHosts(nil); err != nil {
		t.Fatal(err)
	}
	tc, err := tlsHandshake(t, e.connect(t), e.sluiceRoots, "http/1.1")
	if err != nil {
		t.Fatalf("decrypted handshake: %v", err)
	}
	if body := getThrough(t, tc); !strings.HasSuffix(body, testorigin.ContentLengthBody) {
		t.Fatalf("body %q", body)
	}
	ex := e.rec.wait(t)
	if ex.Tunnel != "" || ex.Method != "GET" || !strings.HasPrefix(ex.JA4, "t13d") || ex.JA4[8:10] != "h1" {
		t.Fatalf("decrypted exchange = %+v", ex)
	}
}

// An h2-only client goes straight through, without even probing the origin.
func TestTunnelClientOffersOnlyH2(t *testing.T) {
	auth, roots := testCA(t)
	cert, err := auth.MintLeaf(testorigin.TLSServerName)
	if err != nil {
		t.Fatal(err)
	}
	origin, accepted := startStrictOrigin(t, cert, "h2")
	e := startTunnelEnv(t, origin, roots, nil)
	tc, err := tlsHandshake(t, e.connect(t), roots, "h2")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(tc); string(b) != "proto=h2" {
		t.Fatalf("got %q", b)
	}
	_ = tc.Close()
	ex := e.rec.wait(t)
	if ex.Tunnel != TunnelClientH2 || ex.JA4[8:10] != "h2" {
		t.Fatalf("exchange = %+v", ex)
	}
	if n := accepted.Load(); n != 1 {
		t.Fatalf("origin saw %d connections, want 1 (no probe)", n)
	}
}

// startStrictOrigin is a TLS origin that speaks only the given ALPN
// protocols. With protos other than "h2", an offer of just http/1.1 gets
// alert 120 (no_application_protocol), like a strict h2-only server. (Go
// itself lets http/1.1 clients into an "h2" server, see negotiateALPN.)
// It writes "proto=<negotiated>" and counts connections.
func startStrictOrigin(t *testing.T, cert *tls.Certificate, protos ...string) (string, *atomic.Int64) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: protos})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				_, _ = io.WriteString(c, "proto="+c.(*tls.Conn).ConnectionState().NegotiatedProtocol)
			}()
		}
	}()
	return ln.Addr().String(), &accepted
}

func TestTunnelHostRefusingHTTP11IsRemembered(t *testing.T) {
	auth, roots := testCA(t)
	cert, err := auth.MintLeaf(testorigin.TLSServerName)
	if err != nil {
		t.Fatal(err)
	}
	origin, accepted := startStrictOrigin(t, cert, "x-only")
	e := startTunnelEnv(t, origin, roots, nil)

	for i := range 2 {
		tc, err := tlsHandshake(t, e.connect(t), roots, "x-only", "http/1.1")
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if b, _ := io.ReadAll(tc); string(b) != "proto=x-only" {
			t.Fatalf("round %d: %q", i, b)
		}
		_ = tc.Close()
		if ex := e.rec.wait(t); ex.Tunnel != TunnelHostH2 {
			t.Fatalf("round %d: exchange %+v", i, ex)
		}
	}
	// Round one: probe + tunnel. Round two: remembered, tunnel only.
	if n := accepted.Load(); n != 3 {
		t.Fatalf("origin saw %d connections, want 3", n)
	}
	flags := e.srv.LearnedHosts()
	if len(flags) != 1 || flags[0].Host != testorigin.TLSServerName || flags[0].Reason != TunnelHostH2 {
		t.Fatalf("learned = %+v", flags)
	}
}

// A client that rejects our leaf while the CA is trusted looks pinned: the
// host is flagged, and from then on tunnelled so the app keeps working.
func TestTunnelPinningSuspectedWhenCATrusted(t *testing.T) {
	var asked atomic.Int64
	e := startTestOriginEnv(t, func(c *Config) {
		c.CATrusted = func() bool { asked.Add(1); return true }
	})
	// The "pinned" client: it trusts only the real origin, never Sluice.
	if _, err := tlsHandshake(t, e.connect(t), e.originRoots, "http/1.1"); err == nil {
		t.Fatal("client accepted Sluice's leaf")
	}
	ex := e.rec.wait(t)
	if !ex.PinSuspected || !strings.Contains(ex.Err, "client TLS handshake") || ex.JA4 == "" || asked.Load() != 1 {
		t.Fatalf("exchange = %+v (trust asked %d times)", ex, asked.Load())
	}
	if f := e.srv.LearnedHosts(); len(f) != 1 || f[0].Reason != TunnelPinned {
		t.Fatalf("learned = %+v", f)
	}
	e.expectRawTunnel(t, TunnelPinned, "http/1.1")

	// Forgetting the host brings decryption (and the check) back.
	e.srv.ForgetHost(testorigin.TLSServerName + ".")
	if len(e.srv.LearnedHosts()) != 0 {
		t.Fatal("host not forgotten")
	}
}

// The same abort with an untrusted CA is just "not installed": no flag.
func TestTunnelNoPinningFlagWhenCAUntrusted(t *testing.T) {
	for name, trusted := range map[string]func() bool{"untrusted": func() bool { return false }, "unknown": nil} {
		e := startTestOriginEnv(t, func(c *Config) { c.CATrusted = trusted })
		if _, err := tlsHandshake(t, e.connect(t), e.originRoots, "http/1.1"); err == nil {
			t.Fatal("client accepted Sluice's leaf")
		}
		if ex := e.rec.wait(t); ex.PinSuspected || ex.Tunnel != "" {
			t.Fatalf("%s: exchange = %+v", name, ex)
		}
		if f := e.srv.LearnedHosts(); len(f) != 0 {
			t.Fatalf("%s: learned = %+v", name, f)
		}
	}
}

// A CONNECT followed by something that is not TLS is recorded and closed.
func TestTunnelRejectsNonTLSAfterConnect(t *testing.T) {
	e := startTestOriginEnv(t, nil)
	c := e.connect(t)
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if ex := e.rec.wait(t); !strings.Contains(ex.Err, "ClientHello") {
		t.Fatalf("exchange = %+v", ex)
	}
}

func TestNormalizeBypass(t *testing.T) {
	got, err := NormalizeBypass([]string{" Example.COM. ", "", "*.example.com", "example.com", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "example.com,*.example.com,10.0.0.1" {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"*", "*.", "a.*.com", "http://x.com", "x.com:443", "a b"} {
		if _, err := NormalizeBypass([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMatchBypass(t *testing.T) {
	cases := []struct {
		pat, host string
		want      bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "a.example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "badexample.com", false},
	}
	for _, c := range cases {
		if got := matchBypass(c.pat, c.host); got != c.want {
			t.Errorf("%s vs %s: %v", c.pat, c.host, got)
		}
	}
}

func TestLearnedHostsAreCapped(t *testing.T) {
	p := newTLSPolicy()
	for i := range maxRememberedHosts + 10 {
		p.learn("h"+strconv.Itoa(i)+".test", TunnelPinned)
	}
	if n := len(p.learnedHosts()); n != maxRememberedHosts {
		t.Fatalf("%d hosts remembered", n)
	}
}
