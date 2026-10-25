package engine

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgtlmonk/sluice/internal/live"
)

// DefaultListenAddr is loopback only (CLAUDE.md: never bind wider by default).
const DefaultListenAddr = "127.0.0.1:8080"

// Direction says which message a raw body tap belongs to.
type Direction int

const (
	DirRequest Direction = iota
	DirResponse
)

// Exchange is the summary published for one request/response pair. It holds
// no headers or bodies, so it is safe to log.
type Exchange struct {
	ID        uint64
	Started   time.Time
	Method    string
	Scheme    string // "http", or "https" inside a decrypted CONNECT tunnel
	Host      string // authority from the request target
	Path      string // origin-form path, query included
	Status    int    // status sent to the client; 0 if none was sent
	ReqBytes  int64  // decoded request body bytes forwarded
	RespBytes int64  // decoded response body bytes forwarded
	Duration  time.Duration
	Err       string // proxy-side failure, empty on success

	// TLS facts for exchanges that came through a CONNECT. Requests inside
	// a decrypted tunnel inherit them from the tunnel's ClientHello.
	JA4          string // client TLS fingerprint (see ja4.go); "" for plain HTTP
	Tunnel       string // non-empty: tunnelled raw, not decrypted; the Tunnel* reason
	PinSuspected bool   // the client aborted our handshake while the CA is trusted
}

// Config tunes the proxy. Zero durations fall back to DefaultConfig values.
type Config struct {
	Limits                Limits
	DialTimeout           time.Duration // TCP connect to the origin
	ResponseHeaderTimeout time.Duration // request sent -> response head received
	UpstreamIdleTimeout   time.Duration // max silence on an upstream read/write; pooled conn max idle age
	ClientIdleTimeout     time.Duration // max silence from/to the client, incl. waiting for the next request
	// HeadReadTimeout bounds reading one whole client request head, from its
	// first byte to the blank line. The idle timeouts alone are renewed on
	// every read, so a slowloris client trickling one byte per minute would
	// hold a goroutine forever; this is an absolute cap on the head.
	// (The origin's response head is capped the same way by ResponseHeaderTimeout.)
	HeadReadTimeout time.Duration
	MaxIdlePerHost  int

	// LeafCerts, if set, turns on HTTPS interception: CONNECT tunnels are
	// decrypted with leaf certificates it mints. Nil refuses CONNECT (501).
	LeafCerts LeafMinter
	// UpstreamRootCAs verifies origin certificates on the upstream TLS leg.
	// Nil means the system roots, which is what production wants; tests
	// pass the test origin's own CA.
	UpstreamRootCAs *x509.CertPool
	// BypassHosts are host patterns tunnelled raw without decrypting (see
	// NormalizeBypass). Invalid patterns make the list empty, so callers
	// validate with NormalizeBypass first. SetBypassHosts changes it live.
	BypassHosts []string
	// CATrusted reports whether the OS currently trusts Sluice's root CA.
	// It gates pinning detection: a client that aborts our handshake is
	// only "likely pinned" if it should have trusted the leaf. The engine
	// never asks the OS itself; nil means "unknown", and nothing is flagged.
	// It is called only on such an abort, on the connection goroutine.
	CATrusted func() bool

	// Events, if set, receives one Exchange per request. Publishing never
	// blocks: when the feed is full the event is dropped and counted.
	Events *live.Feed[Exchange]
	// BodyTap, if set, sees the raw wire bytes of every body (chunk framing
	// included) as they stream. It runs inline on the forwarding path, so it
	// must be fast and must not retain the slice.
	BodyTap func(exchangeID uint64, dir Direction, raw []byte)
	// HeadTap, if set, sees each message head exactly as it was received:
	// the client's request head, and the origin's final (non-1xx) response
	// head. For a proxy-generated error response it sees the head the proxy
	// wrote. Same rules as BodyTap: inline, fast, must not retain the slice.
	HeadTap func(exchangeID uint64, dir Direction, rawHead []byte)
	// Done, if set, is called once per published exchange, after the last
	// HeadTap/BodyTap call for that exchange ID. Unlike Events it is not
	// lossy, which is what the storage path needs; it runs inline on the
	// connection goroutine, so it must not block (the storage queue it feeds
	// never does).
	Done func(Exchange)
}

// DefaultConfig returns the production defaults.
func DefaultConfig() Config {
	return Config{
		Limits:                DefaultLimits,
		DialTimeout:           10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		UpstreamIdleTimeout:   90 * time.Second,
		ClientIdleTimeout:     90 * time.Second,
		HeadReadTimeout:       30 * time.Second,
		MaxIdlePerHost:        8,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Limits == (Limits{}) {
		c.Limits = d.Limits
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = d.DialTimeout
	}
	if c.ResponseHeaderTimeout <= 0 {
		c.ResponseHeaderTimeout = d.ResponseHeaderTimeout
	}
	if c.UpstreamIdleTimeout <= 0 {
		c.UpstreamIdleTimeout = d.UpstreamIdleTimeout
	}
	if c.ClientIdleTimeout <= 0 {
		c.ClientIdleTimeout = d.ClientIdleTimeout
	}
	if c.HeadReadTimeout <= 0 {
		c.HeadReadTimeout = d.HeadReadTimeout
	}
	if c.MaxIdlePerHost <= 0 {
		c.MaxIdlePerHost = d.MaxIdlePerHost
	}
	return c
}

// ErrNonLoopback is returned by Listen for a non-loopback address without opt-in.
var ErrNonLoopback = errors.New("refusing to listen on a non-loopback address (explicit opt-in required)")

// CheckLoopback reports whether addr ("host:port") binds only loopback.
// An empty host (":8080") means every interface and is refused. The name
// "localhost" is not trusted as such: /etc/hosts or a resolver can point it
// anywhere, so it is accepted only because Listen pins it to 127.0.0.1
// (see loopbackAddr) instead of letting net.Listen resolve it.
func CheckLoopback(addr string) error {
	_, err := loopbackAddr(addr)
	return err
}

// loopbackAddr validates addr and returns the literal address to bind.
// "localhost" becomes 127.0.0.1, so what is checked is exactly what is bound.
func loopbackAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("%w: %q", ErrNonLoopback, addr)
	}
	return addr, nil
}

// Listen opens the proxy listener. Non-loopback addresses need allowNonLoopback.
func Listen(addr string, allowNonLoopback bool) (net.Listener, error) {
	if !allowNonLoopback {
		bind, err := loopbackAddr(addr)
		if err != nil {
			return nil, err
		}
		addr = bind
	}
	return net.Listen("tcp", addr)
}

// Server is the forward proxy (plain HTTP, plus decrypted CONNECT tunnels
// when Config.LeafCerts is set): one goroutine per client
// connection, keep-alive on both legs, streaming bodies.
type Server struct {
	cfg    Config
	pool   *connPool
	certs  *certCache // nil when interception is off
	policy *tlsPolicy
	nextID atomic.Uint64

	mu      sync.Mutex
	ln      net.Listener
	conns   map[*clientConn]struct{}
	closing bool
	wg      sync.WaitGroup
}

// NewServer returns a Server; call Serve to start it.
func NewServer(cfg Config) *Server {
	cfg = cfg.withDefaults()
	var certs *certCache
	if cfg.LeafCerts != nil {
		certs = newCertCache(cfg.LeafCerts)
	}
	policy := newTLSPolicy()
	_ = policy.setBypass(cfg.BypassHosts) // documented: invalid -> empty
	return &Server{
		cfg:    cfg,
		certs:  certs,
		policy: policy,
		pool:   newConnPool(cfg.MaxIdlePerHost, cfg.UpstreamIdleTimeout),
		conns:  map[*clientConn]struct{}{},
	}
}

// ErrServerClosed is returned by Serve after Shutdown.
var ErrServerClosed = errors.New("proxy: server closed")

// Serve accepts connections on ln until Shutdown.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.ln = ln
	s.mu.Unlock()

	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		cc := s.newClientConn(c)
		if cc == nil {
			_ = c.Close()
			continue
		}
		go func() {
			defer s.wg.Done()
			cc.serve()
		}()
	}
}

// Shutdown stops accepting, closes idle client connections at once, lets
// in-flight exchanges finish, and force-closes whatever is left when ctx ends.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for cc := range s.conns {
		if cc.idle {
			_ = cc.conn.Close()
		}
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	var err error
	select {
	case <-done:
	case <-ctx.Done():
		err = ctx.Err()
		s.mu.Lock()
		for cc := range s.conns {
			_ = cc.conn.Close()
		}
		s.mu.Unlock()
		<-done
	}
	s.pool.closeAll()
	return err
}

func (s *Server) newClientConn(c net.Conn) *clientConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil
	}
	tc := &timeoutConn{Conn: c, readTimeout: s.cfg.ClientIdleTimeout, writeTimeout: s.cfg.ClientIdleTimeout}
	cc := &clientConn{srv: s, conn: tc, br: bufio.NewReader(tc), bw: bufio.NewWriter(tc)}
	s.conns[cc] = struct{}{}
	s.wg.Add(1)
	return cc
}

// setIdle marks a client conn as waiting for its next request. It returns
// false if the server is shutting down, so the conn exits instead of waiting.
func (s *Server) setIdle(cc *clientConn, idle bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cc.idle = idle
	return !s.closing
}

func (s *Server) removeConn(cc *clientConn) {
	s.mu.Lock()
	delete(s.conns, cc)
	s.mu.Unlock()
}

func (s *Server) publish(ex Exchange) {
	if s.cfg.Events != nil {
		s.cfg.Events.Publish(ex) // non-blocking; drops are counted by the feed
	}
	if s.cfg.Done != nil {
		s.cfg.Done(ex)
	}
}

func (s *Server) tapHead(id uint64, dir Direction, raw []byte) {
	if s.cfg.HeadTap != nil {
		s.cfg.HeadTap(id, dir, raw)
	}
}

func (s *Server) tapFor(id uint64, dir Direction) func([]byte) {
	if s.cfg.BodyTap == nil {
		return nil
	}
	tap := s.cfg.BodyTap
	return func(b []byte) { tap(id, dir, b) }
}
