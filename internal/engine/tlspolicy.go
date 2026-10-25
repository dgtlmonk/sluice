package engine

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Why a CONNECT tunnel was passed through raw instead of decrypted.
const (
	TunnelBypass   = "bypass list"
	TunnelPinned   = "pinning suspected"
	TunnelClientH2 = "client offers only h2"
	TunnelHostH2   = "host refuses http/1.1"
)

// maxRememberedHosts caps the pinned and h2-only memories. They are filled
// by what clients and origins do, so without a cap a hostile client could
// grow them without limit. Past the cap new hosts are simply not remembered.
const maxRememberedHosts = 4096

// HostFlag is one host the engine learned to tunnel raw.
type HostFlag struct {
	Host   string
	Reason string // TunnelPinned or TunnelHostH2
	Since  time.Time
}

// tlsPolicy decides, per CONNECT, whether to decrypt or tunnel raw. The
// bypass list is user-set; the pinned and h2-only sets are learned.
type tlsPolicy struct {
	mu      sync.Mutex
	bypass  []string            // normalized patterns: "host" or "*.domain"
	learned map[string]HostFlag // by normalized host
}

func newTLSPolicy() *tlsPolicy { return &tlsPolicy{learned: map[string]HostFlag{}} }

func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".") }

// NormalizeBypass validates and normalizes bypass patterns. A pattern is an
// exact host ("api.example.com", an IP) or "*.example.com", which matches
// every subdomain of example.com but not example.com itself (list both to
// cover both, as in Burp). Blank entries are dropped and duplicates merged.
func NormalizeBypass(patterns []string) ([]string, error) {
	var out []string
	for _, p := range patterns {
		p = normHost(p)
		if p == "" {
			continue
		}
		if !validCertHost(strings.TrimPrefix(p, "*.")) {
			return nil, fmt.Errorf("bypass pattern %q: use host or *.domain", p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func matchBypass(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*"); ok {
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

func (p *tlsPolicy) setBypass(patterns []string) error {
	norm, err := NormalizeBypass(patterns)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.bypass = norm
	p.mu.Unlock()
	return nil
}

func (p *tlsPolicy) bypassList() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.bypass)
}

// tunnelReason returns why this connection must be tunnelled raw, or "" to
// decrypt it. names are the SNI name and the CONNECT host (either may
// match); the client's ALPN list comes from its ClientHello.
func (p *tlsPolicy) tunnelReason(h *clientHello, names ...string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, n := range names {
		n = normHost(n)
		if n == "" {
			continue
		}
		for _, pat := range p.bypass {
			if matchBypass(pat, n) {
				return TunnelBypass
			}
		}
		if f, ok := p.learned[n]; ok {
			return f.Reason
		}
	}
	if h.onlyH2() {
		return TunnelClientH2
	}
	return ""
}

func (p *tlsPolicy) learn(host, reason string) {
	host = normHost(host)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.learned[host]; ok || len(p.learned) >= maxRememberedHosts {
		return
	}
	p.learned[host] = HostFlag{Host: host, Reason: reason, Since: time.Now()}
}

func (p *tlsPolicy) forget(host string) {
	p.mu.Lock()
	delete(p.learned, normHost(host))
	p.mu.Unlock()
}

func (p *tlsPolicy) learnedHosts() []HostFlag {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]HostFlag, 0, len(p.learned))
	for _, f := range p.learned {
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b HostFlag) int { return strings.Compare(a.Host, b.Host) })
	return out
}

// SetBypassHosts replaces the bypass list. It is safe to call while serving;
// it applies to CONNECTs that arrive afterwards.
func (s *Server) SetBypassHosts(patterns []string) error { return s.policy.setBypass(patterns) }

// BypassHosts returns the current (normalized) bypass list.
func (s *Server) BypassHosts() []string { return s.policy.bypassList() }

// LearnedHosts returns the hosts the engine decided to tunnel raw on its own:
// suspected certificate pinning, or origins that refuse HTTP/1.1.
func (s *Server) LearnedHosts() []HostFlag { return s.policy.learnedHosts() }

// ForgetHost drops a learned flag, so the next CONNECT to host is decrypted
// (and re-checked) again.
func (s *Server) ForgetHost(host string) { s.policy.forget(host) }
