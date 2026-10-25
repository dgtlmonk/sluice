package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// LeafMinter signs a TLS server certificate for one host. *ca.Authority
// satisfies it; the engine depends only on this method so it never touches
// the CA's private keys itself.
type LeafMinter interface {
	MintLeaf(host string) (*tls.Certificate, error)
}

// alpnHTTP11 is the only protocol offered on either TLS leg. ALPN
// (Application-Layer Protocol Negotiation, RFC 7301) lets the client list the
// protocols it speaks inside the ClientHello; the server picks one. A browser
// offers ["h2", "http/1.1"]; answering with only "http/1.1" makes it fall back
// to HTTP/1.1, which is the protocol this engine parses. (Real HTTP/2 is M8.)
var alpnHTTP11 = []string{"http/1.1"}

// tunnel is the state of a decrypted CONNECT tunnel. Every request read from
// the client inside it goes to the same origin, over TLS.
type tunnel struct {
	authority  string // Host value for the origin ("example.com", or "h:8443")
	addr       string // host:port to dial (the CONNECT target)
	serverName string // SNI sent upstream and the name the origin cert must match
}

// parseConnectTarget parses a CONNECT request target. CONNECT uses
// authority-form (RFC 9112 §3.2.3): "host:port", nothing else, and the port
// is mandatory because there is no scheme to default it from.
func parseConnectTarget(t string) (host, port string, err error) {
	if t == "" || strings.ContainsAny(t, "/?#@") {
		return "", "", errBadAuthority
	}
	if _, _, err := net.SplitHostPort(t); err != nil {
		return "", "", errBadAuthority // includes a missing port
	}
	host, port, err = splitAuthority(t)
	if err != nil {
		return "", "", err
	}
	if !validCertHost(host) {
		return "", "", errBadAuthority
	}
	return host, port, nil
}

// validCertHost reports whether h is safe to put in a minted certificate:
// an IP literal or a DNS name of LDH labels (letters, digits, hyphen; also
// underscore, which real hostnames use even though DNS hostnames should not).
// Wildcards and anything else are refused: the host comes from the client
// (CONNECT line or SNI), and ca.MintLeaf trusts its caller to have checked.
func validCertHost(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// certCache keeps one minted leaf per host, so a page that opens many
// connections to the same host signs one certificate, not one per handshake.
// Unbounded for now; an LRU is on the SPEC.md optimization backlog.
type certCache struct {
	minter LeafMinter
	mu     sync.Mutex
	certs  map[string]*tls.Certificate
}

func newCertCache(m LeafMinter) *certCache {
	return &certCache{minter: m, certs: map[string]*tls.Certificate{}}
}

func (c *certCache) get(host string) (*tls.Certificate, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !validCertHost(host) {
		return nil, fmt.Errorf("refusing to mint a certificate for %q", host)
	}
	// Minting under the lock serializes signing, which also stops two
	// handshakes for the same new host from both signing. Signing with the
	// shared leaf key is one RSA signature, so the wait is short.
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.certs[host]; ok {
		return cert, nil
	}
	cert, err := c.minter.MintLeaf(host)
	if err != nil {
		return nil, err
	}
	c.certs[host] = cert
	return cert, nil
}

// prefixConn replays bytes that were already read into a bufio.Reader
// before reading from the socket. A client may send its ClientHello right
// behind the CONNECT head without waiting for the 200; those bytes sit in
// the HTTP reader's buffer and must reach the TLS layer first.
type prefixConn struct {
	net.Conn
	pending []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pending) > 0 {
		n := copy(b, p.pending)
		p.pending = p.pending[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// handleConnect turns the client connection into a decrypted tunnel:
//
//  1. Validate the CONNECT target and reply "200 Connection Established".
//     From then on the client believes it has a raw TCP pipe to the origin.
//  2. Run a TLS server handshake on that pipe. The client's ClientHello
//     carries SNI (Server Name Indication, RFC 6066): the hostname it wants,
//     sent in cleartext because the server must pick a certificate before
//     any key exists. GetCertificate mints (or reuses) a leaf for that name,
//     signed by Sluice's root CA, which the user's machine trusts.
//  3. Swap the connection's reader/writer for the decrypted TLS stream.
//     serve's loop then reads ordinary HTTP/1.1 requests from inside it.
//
// The upstream TLS leg is dialed per request through the pool (see dial),
// so the origin's real certificate is verified there, against system roots.
// It reports whether serve should keep reading (now from the tunnel).
func (cc *clientConn) handleConnect(x *exchange) bool {
	s := cc.srv
	if cc.tunnel != nil {
		x.ex.Err = "CONNECT inside a tunnel"
		cc.reject(x, 400, x.ex.Err)
		return false
	}
	if s.certs == nil {
		x.ex.Err = "HTTPS interception is off (no root CA loaded)"
		cc.reject(x, 501, x.ex.Err)
		return false
	}
	host, port, err := parseConnectTarget(x.req.Target)
	if err != nil {
		x.ex.Err = "CONNECT target: " + err.Error()
		cc.reject(x, 400, x.ex.Err)
		return false
	}
	// A CONNECT with a body is meaningless (RFC 9110 §9.3.6) and would put
	// non-TLS bytes in front of the ClientHello.
	if x.req.Framing.Kind != FramingNone {
		x.ex.Err = "CONNECT with a body"
		cc.reject(x, 400, x.ex.Err)
		return false
	}
	x.ex.Host = net.JoinHostPort(host, port)
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "443" {
		authority += ":" + port
	}

	_, _ = cc.bw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := cc.bw.Flush(); err != nil {
		return false
	}

	pending, _ := cc.br.Peek(cc.br.Buffered())
	raw := &prefixConn{Conn: cc.conn.Conn, pending: append([]byte(nil), pending...)}
	tc := tls.Server(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: alpnHTTP11,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// No SNI happens for IP-literal targets (clients never send an
			// IP in SNI); the CONNECT host is the name the client expects.
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return s.certs.get(name)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.HeadReadTimeout)
	err = tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		// The client aborted (often: it does not trust the root CA) or spoke
		// something that is not TLS. Nothing can be answered on a half-done
		// handshake; record why and close.
		x.ex.Err = "client TLS handshake: " + err.Error()
		_ = tc.Close()
		return false
	}

	serverName := tc.ConnectionState().ServerName
	if serverName == "" {
		serverName = host
	}
	tconn := &timeoutConn{Conn: tc, readTimeout: s.cfg.ClientIdleTimeout, writeTimeout: s.cfg.ClientIdleTimeout}
	s.mu.Lock() // Shutdown reads cc.conn under mu
	cc.conn = tconn
	s.mu.Unlock()
	cc.br = bufio.NewReader(tconn)
	cc.bw = bufio.NewWriter(tconn)
	cc.tunnel = &tunnel{authority: authority, addr: x.ex.Host, serverName: strings.TrimSuffix(serverName, ".")}
	// The CONNECT itself is plumbing, not an exchange worth a history row;
	// the requests inside the tunnel are. Failed CONNECTs (above) are kept.
	x.silent = true
	return true
}

// tunnelTarget maps a request read inside a tunnel to its origin. Inside a
// tunnel the client talks to "the server", so it uses origin-form ("/path").
func (t *tunnel) target(reqTarget string) (proxyTarget, error) {
	if !strings.HasPrefix(reqTarget, "/") {
		return proxyTarget{}, errors.New("requests inside a CONNECT tunnel must use origin-form (/path)")
	}
	return proxyTarget{authority: t.authority, addr: t.addr, path: reqTarget, tls: true, serverName: t.serverName}, nil
}

// dialTLS wraps a fresh TCP connection to the origin in a TLS client. The
// origin's certificate chain is verified against cfg.UpstreamRootCAs (nil
// means the system roots) and must match serverName, exactly as a browser
// would check it. Sluice decrypts traffic; it must never hide a bad origin
// certificate from the user by accepting it silently.
func (s *Server) dialTLS(c net.Conn, serverName string) (net.Conn, error) {
	tc := tls.Client(c, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    s.cfg.UpstreamRootCAs,
		NextProtos: alpnHTTP11,
	})
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DialTimeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("origin TLS handshake: %w", err)
	}
	// An origin that ignores ALPN negotiates nothing, which means HTTP/1.1.
	// crypto/tls already refuses a protocol that was not offered.
	if p := tc.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" {
		_ = tc.Close()
		return nil, fmt.Errorf("origin negotiated %q", p)
	}
	return tc, nil
}
