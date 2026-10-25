package engine

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/ca"
	"github.com/dgtlmonk/sluice/internal/testorigin"
)

// testCA creates a throwaway root CA in a temp dir. Nothing is installed in
// any keychain or trust store: the test client trusts it via RootCAs.
func testCA(t *testing.T) (*ca.Authority, *x509.CertPool) {
	t.Helper()
	secret := make([]byte, ca.SecretSize)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	a, err := ca.LoadOrCreate(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.Certificate())
	return a, pool
}

// countingMinter counts how often a leaf is actually signed.
type countingMinter struct {
	inner LeafMinter
	n     atomic.Int64
}

func (c *countingMinter) MintLeaf(host string) (*tls.Certificate, error) {
	c.n.Add(1)
	return c.inner.MintLeaf(host)
}

type mitmEnv struct {
	proxy   string
	origin  string
	clients *x509.CertPool // trusts the Sluice test root
	minter  *countingMinter
	rec     *hookRecorder
}

func startMITM(t *testing.T, trustOrigin bool) *mitmEnv {
	t.Helper()
	origin, originRoots, stop := testorigin.StartTLS()
	t.Cleanup(stop)
	auth, clientRoots := testCA(t)
	m := &countingMinter{inner: auth}
	rec := newHookRecorder()
	rec.done = make(chan Exchange, 16)
	cfg := rec.config()
	cfg.LeafCerts = m
	if trustOrigin {
		cfg.UpstreamRootCAs = originRoots
	} else {
		// A pool without the origin's CA: what a real origin with a bad
		// certificate looks like from the proxy's side.
		cfg.UpstreamRootCAs = x509.NewCertPool()
	}
	proxy, _ := startProxy(t, cfg)
	return &mitmEnv{proxy: proxy, origin: origin, clients: clientRoots, minter: m, rec: rec}
}

// connectTLS opens CONNECT origin through the proxy and runs the client TLS
// handshake with serverName as SNI (empty: none, as for an IP target).
func (e *mitmEnv) connectTLS(t *testing.T, serverName string, alpn []string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	rc := dialProxy(t, e.proxy)
	rc.send("CONNECT " + e.origin + " HTTP/1.1\r\nHost: " + e.origin + "\r\n\r\n")
	resp, err := http.ReadResponse(rc.br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status %d", resp.StatusCode)
	}
	if rc.br.Buffered() != 0 {
		t.Fatal("proxy sent bytes after the 200")
	}
	cfg := &tls.Config{RootCAs: e.clients, NextProtos: alpn, ServerName: serverName}
	if serverName == "" {
		host, _, _ := net.SplitHostPort(e.origin)
		cfg.ServerName = host // an IP: Go verifies the IP SAN and sends no SNI
	}
	tc := tls.Client(rc.conn, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return tc, bufio.NewReader(tc)
}

// readResp parses one response with net/http and returns status and body.
func readResp(t *testing.T, br *bufio.Reader, method string) (int, string) {
	t.Helper()
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// A browser offers h2 first; the proxy must answer http/1.1, mint a leaf the
// client accepts, and relay requests over a verified TLS upstream.
func TestMITMDecryptsAndForcesHTTP11(t *testing.T) {
	e := startMITM(t, true)
	tc, br := e.connectTLS(t, testorigin.TLSServerName, []string{"h2", "http/1.1"})

	st := tc.ConnectionState()
	if st.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("ALPN = %q, want http/1.1", st.NegotiatedProtocol)
	}
	leaf := st.PeerCertificates[0]
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != testorigin.TLSServerName {
		t.Fatalf("leaf SAN = %v", leaf.DNSNames)
	}

	_, _ = io.WriteString(tc, "GET "+testorigin.PathContentLength+" HTTP/1.1\r\nHost: "+testorigin.TLSServerName+"\r\n\r\n")
	status, body := readResp(t, br, "GET")
	if status != 200 || body != testorigin.ContentLengthBody {
		t.Fatalf("got %d %q", status, body)
	}
	ex := e.rec.wait(t)
	if ex.Scheme != "https" || ex.Method != "GET" || ex.Path != testorigin.PathContentLength || ex.Err != "" {
		t.Fatalf("exchange = %+v", ex)
	}
	_, port, _ := net.SplitHostPort(e.origin)
	if ex.Host != testorigin.TLSServerName+":"+port && ex.Host != "127.0.0.1:"+port {
		t.Fatalf("exchange host = %q", ex.Host)
	}
	// The CONNECT itself is not a history row.
	select {
	case extra := <-e.rec.done:
		t.Fatalf("unexpected extra exchange %+v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

// No SNI (IP target): the leaf is minted for the CONNECT host's IP.
func TestMITMIPTargetWithoutSNI(t *testing.T) {
	e := startMITM(t, true)
	tc, br := e.connectTLS(t, "", []string{"http/1.1"})
	leaf := tc.ConnectionState().PeerCertificates[0]
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("leaf IPs = %v", leaf.IPAddresses)
	}
	_, _ = io.WriteString(tc, "GET "+testorigin.PathChunked+" HTTP/1.1\r\nHost: x\r\n\r\n")
	status, body := readResp(t, br, "GET")
	if status != 200 || body != testorigin.ChunkedBody() {
		t.Fatalf("got %d %q", status, body)
	}
}

// Keep-alive inside the tunnel, and one cached leaf across tunnels.
func TestMITMKeepAliveAndLeafCache(t *testing.T) {
	e := startMITM(t, true)
	for range 2 {
		tc, br := e.connectTLS(t, testorigin.TLSServerName, nil)
		for range 2 {
			_, _ = io.WriteString(tc, "GET "+testorigin.PathKeepAlive+" HTTP/1.1\r\nHost: h\r\n\r\n")
			if _, body := readResp(t, br, "GET"); body != testorigin.KeepAliveBody {
				t.Fatalf("body %q", body)
			}
		}
		_ = tc.Close()
	}
	if n := e.minter.n.Load(); n != 1 {
		t.Fatalf("minted %d leaves, want 1 (cached)", n)
	}
}

// An origin whose certificate does not verify gets a 502 inside the tunnel,
// never a silently accepted connection.
func TestMITMRejectsUntrustedOrigin(t *testing.T) {
	e := startMITM(t, false)
	tc, br := e.connectTLS(t, testorigin.TLSServerName, nil)
	_, _ = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	status, body := readResp(t, br, "GET")
	if status != 502 || !strings.Contains(body, "origin TLS handshake") {
		t.Fatalf("got %d %q", status, body)
	}
	if ex := e.rec.wait(t); ex.Scheme != "https" || !strings.Contains(ex.Err, "certificate") {
		t.Fatalf("exchange = %+v", ex)
	}
}

// Inside a tunnel only origin-form is accepted, and CONNECT is refused.
func TestMITMTunnelRejectsOddTargets(t *testing.T) {
	for _, raw := range []string{
		"GET http://other.test/ HTTP/1.1\r\nHost: h\r\n\r\n",
		"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n",
	} {
		e := startMITM(t, true)
		tc, br := e.connectTLS(t, testorigin.TLSServerName, nil)
		_, _ = io.WriteString(tc, raw)
		method := strings.SplitN(raw, " ", 2)[0]
		if status, _ := readResp(t, br, method); status != 400 {
			t.Fatalf("%q: status %d", raw, status)
		}
	}
}

func TestMITMBadConnectTargets(t *testing.T) {
	e := startMITM(t, true)
	for _, target := range []string{"a.test", "u@a.test:443", "a.test:0", "*.a.test:443", "a b:443", "a.test:443/x", "[::1]"} {
		rc := dialProxy(t, e.proxy)
		rc.send("CONNECT " + target + " HTTP/1.1\r\nHost: x\r\n\r\n")
		if resp, _ := rc.read("CONNECT"); resp.StatusCode != 400 {
			t.Errorf("%q: status %d, want 400", target, resp.StatusCode)
		}
	}
}

// A client that does not trust the root aborts the handshake; the proxy
// records the failed CONNECT and closes.
func TestMITMClientHandshakeFailureRecorded(t *testing.T) {
	e := startMITM(t, true)
	rc := dialProxy(t, e.proxy)
	rc.send("CONNECT " + e.origin + " HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(rc.br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close() // a 2xx to CONNECT has no body; the tunnel follows
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status %d", resp.StatusCode)
	}
	tc := tls.Client(rc.conn, &tls.Config{ServerName: testorigin.TLSServerName, RootCAs: x509.NewCertPool()})
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake succeeded with an untrusted root")
	}
	ex := e.rec.wait(t)
	if ex.Method != "CONNECT" || !strings.Contains(ex.Err, "client TLS handshake") {
		t.Fatalf("exchange = %+v", ex)
	}
}

// net/http as the reference client: its Transport speaks CONNECT and TLS on
// its own, so this checks interop with a real implementation. ServerName is
// overridden so no DNS lookup of example.com happens.
func TestMITMNetHTTPClientOracle(t *testing.T) {
	e := startMITM(t, true)
	pu := &url.URL{Scheme: "http", Host: e.proxy}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:             http.ProxyURL(pu),
		TLSClientConfig:   &tls.Config{RootCAs: e.clients, ServerName: testorigin.TLSServerName},
		ForceAttemptHTTP2: true, // offers h2; the proxy must still pick http/1.1
	}}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get("https://" + e.origin + testorigin.PathSSE)
			if err != nil {
				t.Error(err)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.ProtoMajor != 1 || string(b) != testorigin.SSEBody() {
				t.Errorf("proto %s body %q", resp.Proto, b)
			}
		}()
	}
	wg.Wait()
}

func TestValidCertHost(t *testing.T) {
	good := []string{"example.com", "a-b.c_d.test", "127.0.0.1", "::1", "localhost", "example.com."}
	bad := []string{"", "*.example.com", "-a.com", "a-.com", "a..b", "a b", strings.Repeat("a", 64) + ".com", "ex\x00.com"}
	for _, h := range good {
		if !validCertHost(h) {
			t.Errorf("%q rejected", h)
		}
	}
	for _, h := range bad {
		if validCertHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestPoolKeySeparatesTLSAndServerName(t *testing.T) {
	plain := proxyTarget{addr: "h:443"}
	a := proxyTarget{addr: "h:443", tls: true, serverName: "a.test"}
	b := proxyTarget{addr: "h:443", tls: true, serverName: "b.test"}
	if poolKey(plain) == poolKey(a) || poolKey(a) == poolKey(b) {
		t.Fatal("pool keys collide")
	}
}
