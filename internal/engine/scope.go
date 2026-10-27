package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scope is the list of hosts Sluice may actively send to. It guards the
// "active" tools — Repeater now, Fuzzer, AI attacks and MCP send_request
// later — which make Sluice itself the client. Passive proxying of a
// browser's own traffic is never scope-limited: there the browser chose the
// target, and Sluice only watches.
//
// The rule (CLAUDE.md, SPEC.md "Pipeline"): scope is enforced here, in the
// engine, not only in the UI. An active sender must open every connection
// through Scope.Dial, and must pass every redirect hop through
// Scope.Redirect before following it. Both re-check the host against the
// current list, so a sender cannot reach an out-of-scope host by mistake,
// and a 3xx from an in-scope site cannot bounce Sluice somewhere else (the
// SSRF-style escape a tester must never cause).
//
// What is checked: the host name or literal IP the connection is opened to.
// What is NOT checked yet: the IP a host *name* resolves to. An in-scope
// name whose DNS points outside scope (DNS rebinding) is not caught; see
// SPEC.md "Known gaps".
//
// Patterns:
//
//	localhost        exact host name (case-insensitive, trailing dot ignored)
//	127.0.0.1, ::1   exact IP; IPv4-mapped IPv6 (::ffff:127.0.0.1) is the same IP
//	*.test           every subdomain of "test" ("a.test", "a.b.test"), but
//	                 not "test" itself and never an IP (list both to cover both)
//
// Ports are not part of a pattern: an in-scope host is in scope on every
// port. Scope is safe for concurrent use; Set applies to the next check.
type Scope struct {
	mu    sync.RWMutex
	list  []string    // normalized patterns, as shown to the user
	rules []scopeRule // the same patterns, parsed for matching

	// dial opens the TCP connection once the target passed the check.
	// Tests replace it to prove that a refused target is never dialled.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DefaultScope is the scope of a fresh install (SPEC.md, Test targets and
// scope): the local machine and the reserved .test TLD (RFC 6761 §6.2),
// which never resolves on the public internet.
var DefaultScope = []string{"localhost", "127.0.0.1", "*.test"}

// ActiveDialTimeout bounds the TCP connect of an active send when the
// caller's context has no earlier deadline.
const ActiveDialTimeout = 10 * time.Second

// ErrOutOfScope is wrapped by every refusal of a well-formed target that is
// not in the scope list. Test with errors.Is.
var ErrOutOfScope = errors.New("out of scope")

// ErrBadTarget is wrapped by every refusal of a target that could not be
// parsed safely. Such targets are refused outright, never guessed at: a URL
// that two parsers read differently is how scope checks get bypassed.
var ErrBadTarget = errors.New("invalid target")

// scopeRule is one parsed pattern. Exactly one of ip, name, suffix is set.
type scopeRule struct {
	ip     netip.Addr // exact IP pattern (unmapped)
	name   string     // exact host name
	suffix string     // ".domain" for "*.domain"
}

func (r scopeRule) match(h scopeHost) bool {
	switch {
	case r.ip.IsValid():
		return h.ip.IsValid() && h.ip == r.ip
	case h.ip.IsValid():
		// An IP host only matches an IP pattern. "*.0.1" must never cover
		// "127.0.0.1": wildcards are about DNS names, not address ranges.
		return false
	case r.suffix != "":
		// "*.test" -> suffix ".test". The leading dot is what stops
		// "evil-test" or "eviltest" from matching, and the length check
		// stops ".test" itself from matching.
		return len(h.name) > len(r.suffix) && strings.HasSuffix(h.name, r.suffix)
	default:
		return h.name == r.name
	}
}

// scopeHost is a target host after normalization: an IP or a DNS name.
type scopeHost struct {
	ip   netip.Addr // valid for a literal IP
	name string     // lower-case DNS name, no trailing dot; "" for an IP
}

// String is the host as it is dialled and shown: an IP in canonical form
// (IPv6 without brackets), or the normalized name.
func (h scopeHost) String() string {
	if h.ip.IsValid() {
		return h.ip.String()
	}
	return h.name
}

// NewScope returns a scope with the given patterns (see NormalizeScope).
func NewScope(patterns []string) (*Scope, error) {
	s := &Scope{dial: (&net.Dialer{Timeout: ActiveDialTimeout}).DialContext}
	if _, err := s.Set(patterns); err != nil {
		return nil, err
	}
	return s, nil
}

// NormalizeScope validates patterns and returns them normalized: trimmed,
// lower-case, no trailing dot, IPs in canonical form. Blank entries are
// dropped and duplicates merged. Anything else that is not a host, an IP or
// "*.domain" is an error naming the pattern: a URL, a port, a bare "*",
// userinfo, an IPv6 zone, a wildcard over an IP, or a host written as a
// number in a non-standard IPv4 form ("127.1", "2130706433", "0x7f.1").
func NormalizeScope(patterns []string) ([]string, error) {
	list, _, err := parseScope(patterns)
	return list, err
}

func parseScope(patterns []string) ([]string, []scopeRule, error) {
	list := []string{}
	var rules []scopeRule
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		norm, rule, err := parseScopePattern(p)
		if err != nil {
			return nil, nil, fmt.Errorf("scope pattern %q: %w", p, err)
		}
		if !slices.Contains(list, norm) {
			list = append(list, norm)
			rules = append(rules, rule)
		}
	}
	return list, rules, nil
}

func parseScopePattern(p string) (string, scopeRule, error) {
	if strings.Contains(p, "://") || strings.Contains(p, "/") {
		return "", scopeRule{}, errors.New("not a URL or path; list the host only")
	}
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		h, err := parseHost(rest)
		if err != nil {
			return "", scopeRule{}, errors.New("use host, IP or *.domain")
		}
		if h.ip.IsValid() {
			return "", scopeRule{}, errors.New("a wildcard cannot cover an IP address")
		}
		return "*." + h.name, scopeRule{suffix: "." + h.name}, nil
	}
	if strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]") {
		p = p[1 : len(p)-1] // "[::1]" is accepted as "::1"
		if !strings.Contains(p, ":") {
			// Brackets are for IPv6 only. "[a.test]" and "[127.0.0.1]" are
			// refused here exactly as Check refuses them as hosts, so the
			// pattern parser and the target parser never disagree.
			return "", scopeRule{}, errors.New("brackets are for IPv6 addresses only")
		}
	} else if strings.Count(p, ":") == 1 {
		// "host:8080": one colon cannot be IPv6. Say why, rather than a
		// generic error, because a tester will try it.
		return "", scopeRule{}, errors.New("ports are not part of a scope pattern; list the host only")
	}
	h, err := parseHost(p)
	if err != nil {
		return "", scopeRule{}, errors.New("use host, IP or *.domain")
	}
	if h.ip.IsValid() {
		return h.String(), scopeRule{ip: h.ip}, nil
	}
	return h.name, scopeRule{name: h.name}, nil
}

// parseHost normalizes one host (no brackets, no port). It accepts a DNS
// name or a literal IP in its one standard form, and refuses everything a
// resolver or URL parser might read differently from this check.
func parseHost(s string) (scopeHost, error) {
	// IPv6 (and IPv4) literals. netip refuses leading zeros ("0177.0.0.1"),
	// short forms ("127.1") and anything with trailing junk, which is what
	// we want: there is exactly one way to write an IP here.
	if strings.Contains(s, ":") {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is6() {
			return scopeHost{}, ErrBadTarget
		}
		if ip.Zone() != "" {
			// "fe80::1%en0": a link-local address depends on the
			// interface; there is no sane scope rule for it.
			return scopeHost{}, ErrBadTarget
		}
		// ::ffff:127.0.0.1 is how IPv6 sockets spell an IPv4 address. It
		// reaches the same host as 127.0.0.1, so compare it as that.
		return scopeHost{ip: ip.Unmap()}, nil
	}
	s = strings.ToLower(s)
	// One trailing dot is the DNS root ("localhost." is "localhost"). Two
	// would be an empty label, refused below.
	s = strings.TrimSuffix(s, ".")
	if ip, err := netip.ParseAddr(s); err == nil {
		return scopeHost{ip: ip}, nil
	}
	if endsInNumber(s) {
		// Not a valid dotted-quad, yet the last label is numeric. Many
		// resolvers (getaddrinfo, WHATWG URL parsers) still read it as an
		// IPv4 address: "127.1", "2130706433", "0x7f.0.0.1" and
		// "0177.0.0.1" all mean 127.0.0.1. Refuse, so the check and the
		// connection can never disagree about where the target is.
		return scopeHost{}, ErrBadTarget
	}
	if !validDNSName(s) {
		return scopeHost{}, ErrBadTarget
	}
	return scopeHost{name: s}, nil
}

// endsInNumber is the WHATWG URL "ends in a number" test: the last label is
// all decimal digits, or "0x" followed by hex digits. Such a host is parsed
// as IPv4 by browsers.
func endsInNumber(s string) bool {
	labels := strings.Split(s, ".")
	last := labels[len(labels)-1]
	if last == "" {
		return false
	}
	if allIn(last, "0123456789") {
		return true
	}
	if hex, ok := strings.CutPrefix(last, "0x"); ok {
		return allIn(hex, "0123456789abcdef")
	}
	return false
}

func allIn(s, set string) bool {
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(set, rune(s[i])) {
			return false
		}
	}
	return true
}

// validDNSName accepts ASCII letter-digit-hyphen labels (underscore too,
// which real service names use). It refuses "%", "\", "@", spaces, control
// characters and non-ASCII: percent-encoding, backslashes and Unicode
// look-alikes are classic ways to make a check and a resolver see
// different hosts. Internationalized names must be written in punycode.
func validDNSName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'; !ok {
				return false
			}
		}
	}
	return true
}

// reservedTLDs are top-level names that never resolve on the public
// internet (RFC 2606, RFC 6761, and ICANN's 2024 ".internal"), so "*.test"
// or "*.internal" cannot reach someone else's site.
var reservedTLDs = []string{"test", "localhost", "invalid", "example", "internal", "local"}

// ScopeWarnings returns a human-readable warning for each valid but
// over-broad pattern in list: a wildcard over a whole public top-level
// domain ("*.com" puts every .com site in scope), or an unspecified IP
// ("0.0.0.0", "::"), which reaches the local machine on many systems
// without saying so. Such patterns are allowed, because a lab may need
// them, but the user should see what they wrote. It cannot know multi-label
// public suffixes like "*.co.uk"; that would need the Public Suffix List.
func ScopeWarnings(list []string) []string {
	warnings := []string{}
	for _, p := range list {
		if rest, ok := strings.CutPrefix(p, "*."); ok {
			if !strings.Contains(rest, ".") && !slices.Contains(reservedTLDs, rest) {
				warnings = append(warnings, fmt.Sprintf("%s covers every host under the public .%s domain", p, rest))
			}
			continue
		}
		if ip, err := netip.ParseAddr(p); err == nil && ip.IsUnspecified() {
			warnings = append(warnings, fmt.Sprintf("%s is the unspecified address; it reaches this machine on many systems", p))
		}
	}
	return warnings
}

// Set validates and replaces the patterns. On error the old list stays.
// It returns the normalized list.
func (s *Scope) Set(patterns []string) ([]string, error) {
	list, rules, err := parseScope(patterns)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.list, s.rules = list, rules
	s.mu.Unlock()
	return slices.Clone(list), nil
}

// List returns the normalized patterns.
func (s *Scope) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.list)
}

// Target is where an active send connects: scheme, host and port. It is an
// origin, not a full URL. The scope check applies to Host, the address that
// is actually dialled, never to a Host header or SNI a sender writes later.
type Target struct {
	Scheme string // "http" or "https"
	Host   string // DNS name or IP, normalized; IPv6 without brackets
	Port   int
}

// Addr is the host:port to dial.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// TLS reports whether the connection must be wrapped in TLS.
func (t Target) TLS() bool { return t.Scheme == "https" }

// String is the origin, e.g. "https://a.test:8443" or "http://[::1]:80".
func (t Target) String() string { return t.Scheme + "://" + t.Addr() }

// Check normalizes t and reports whether it is in scope. Every refusal
// wraps ErrOutOfScope or ErrBadTarget. The error names the host only, never
// a URL, so no credential or token in a URL can end up in a log.
func (s *Scope) Check(t Target) (Target, error) {
	scheme := strings.ToLower(t.Scheme)
	if scheme != "http" && scheme != "https" {
		return Target{}, fmt.Errorf("%w: scheme must be http or https", ErrBadTarget)
	}
	if t.Port < 1 || t.Port > 65535 {
		return Target{}, fmt.Errorf("%w: port %d", ErrBadTarget, t.Port)
	}
	raw := t.Host
	bracketed := strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]")
	if bracketed {
		raw = raw[1 : len(raw)-1]
	}
	h, err := parseHost(raw)
	if err == nil && bracketed && !strings.Contains(raw, ":") {
		err = ErrBadTarget // brackets are for IPv6 only: "[127.0.0.1]" is malformed
	}
	if err != nil {
		return Target{}, fmt.Errorf("%w: host is not a plain DNS name or IP", ErrBadTarget)
	}
	if !s.allows(h) {
		return Target{}, fmt.Errorf("%w: %s is not in the scope list", ErrOutOfScope, h)
	}
	return Target{Scheme: scheme, Host: h.String(), Port: t.Port}, nil
}

func (s *Scope) allows(h scopeHost) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.ContainsFunc(s.rules, func(r scopeRule) bool { return r.match(h) })
}

// CheckURL parses an absolute http(s) URL and checks its host. It returns
// the target and the request path in origin-form ("/a?b"; the fragment is
// dropped, since it is never sent).
func (s *Scope) CheckURL(rawURL string) (Target, string, error) {
	t, path, err := parseTargetURL(rawURL)
	if err != nil {
		return Target{}, "", err
	}
	if t, err = s.Check(t); err != nil {
		return Target{}, "", err
	}
	return t, path, nil
}

// Redirect resolves a redirect's Location against the request it answered
// (from + fromPath) and checks the next hop. Follow a redirect only if this
// returns no error: an in-scope site that answers "302 Location:
// http://169.254.169.254/" must not make Sluice fetch cloud metadata.
//
// Location may be absolute ("https://b.test/x"), scheme-relative
// ("//b.test/x", which keeps from's scheme), path-absolute ("/x") or
// relative ("x", "../x", "?q"). Schemes other than http and https, and any
// backslash, are refused: browsers treat "\" as "/" in some positions, so
// "/\evil.example" would be a path to one parser and a host to another.
func (s *Scope) Redirect(from Target, fromPath, location string) (Target, string, error) {
	loc := strings.TrimSpace(location)
	if loc == "" || badURLChars(loc) {
		return Target{}, "", fmt.Errorf("%w: redirect location has a forbidden character", ErrBadTarget)
	}
	switch {
	case hasScheme(loc):
		return s.CheckURL(loc)
	case strings.HasPrefix(loc, "//"):
		// Network-path reference (RFC 3986 §4.2): a new host, same scheme.
		return s.CheckURL(from.Scheme + ":" + loc)
	}
	// Same origin as the request: still re-checked, because the scope may
	// have changed since the first hop was sent.
	t, err := s.Check(from)
	if err != nil {
		return Target{}, "", err
	}
	return t, resolvePath(fromPath, stripFragment(loc)), nil
}

// Dial checks t and, only if it is in scope, opens a TCP connection to it.
// This is the one way active senders reach the network. It never resolves
// or dials a refused host, and it resolves an allowed name exactly as
// checked (see dialAddr). TLS, if t.TLS(), is the caller's next step.
//
// "The one way" is enforced by TestOnlyScopeDialsActively (a source scan
// that fails if new engine code dials on its own), not by the type system.
func (s *Scope) Dial(ctx context.Context, t Target) (net.Conn, Target, error) {
	t, err := s.Check(t)
	if err != nil {
		return nil, Target{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ActiveDialTimeout)
		defer cancel()
	}
	c, err := s.dial(ctx, "tcp", t.dialAddr())
	if err != nil {
		return nil, Target{}, err
	}
	return c, t, nil
}

// dialAddr is the address Dial hands to the resolver. A host name is sent
// rooted, with a trailing dot ("a.test." not "a.test"), and an IP as is.
//
// Why the dot: a name without one is "relative", and the system resolver
// may try it with the machine's DNS search domains appended. On a network
// whose search domain is "lan", "nothere.test" that gets NXDOMAIN is
// retried as "nothere.test.lan" — a host the scope check never saw, and one
// the local network (or whoever runs its DNS) controls. A rooted name is
// looked up exactly as written, so the name that was checked is the name
// that is resolved. Only the dialled address carries the dot: t.Host, the
// Host header and SNI keep the plain name, as servers expect.
func (t Target) dialAddr() string {
	host := t.Host
	if _, err := netip.ParseAddr(host); err != nil {
		host += "."
	}
	return net.JoinHostPort(host, strconv.Itoa(t.Port))
}

// parseTargetURL splits "scheme://authority/path?query#fragment" (RFC 3986
// §3) by hand. The authority ends at the first "/", "?" or "#": that rule
// is what makes "http://evil.example#@127.0.0.1/" point at evil.example
// (the "@127.0.0.1" is fragment), the reading a browser takes.
func parseTargetURL(raw string) (Target, string, error) {
	if badURLChars(raw) {
		return Target{}, "", fmt.Errorf("%w: URL has a forbidden character", ErrBadTarget)
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || !hasScheme(raw) {
		return Target{}, "", fmt.Errorf("%w: not an absolute http(s) URL", ErrBadTarget)
	}
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		// gopher:, file:, dict:, ftp: ... the protocols SSRF payloads use
		// to talk to non-HTTP services. Active sends speak http(s) only.
		return Target{}, "", fmt.Errorf("%w: scheme must be http or https", ErrBadTarget)
	}
	end := strings.IndexAny(rest, "/?#")
	authority, path := rest, "/"
	if end >= 0 {
		authority, path = rest[:end], stripFragment(rest[end:])
		switch {
		case path == "":
			path = "/"
		case path[0] == '?':
			path = "/" + path
		}
	}
	if strings.Contains(authority, "@") {
		// Userinfo: "http://127.0.0.1@evil.example/" goes to evil.example.
		// Deprecated for http (RFC 9110 §4.2.4) and only ever useful to
		// disguise a host, so refused. The error does not echo it: it may
		// hold a password.
		return Target{}, "", fmt.Errorf("%w: userinfo (user@host) is not allowed", ErrBadTarget)
	}
	host, port, err := splitURLAuthority(authority, scheme)
	if err != nil {
		return Target{}, "", err
	}
	return Target{Scheme: scheme, Host: host, Port: port}, path, nil
}

// splitURLAuthority parses host[:port] or [v6][:port]. An empty port
// ("host:") is refused rather than defaulted: strict and unambiguous.
func splitURLAuthority(a, scheme string) (string, int, error) {
	bad := fmt.Errorf("%w: malformed host or port", ErrBadTarget)
	host, port := a, "443"
	if scheme == "http" {
		port = "80"
	}
	switch {
	case strings.HasPrefix(a, "["):
		closeIdx := strings.Index(a, "]")
		if closeIdx < 0 {
			return "", 0, bad
		}
		host = a[:closeIdx+1] // brackets kept; Check strips them
		if tail := a[closeIdx+1:]; tail != "" {
			p, ok := strings.CutPrefix(tail, ":")
			if !ok {
				return "", 0, bad
			}
			port = p
		}
	case strings.Contains(a, ":"):
		var ok bool
		host, port, ok = strings.Cut(a, ":")
		if !ok || strings.Contains(port, ":") {
			return "", 0, bad // a bare IPv6 must be bracketed
		}
	}
	if host == "" || port == "" || !allIn(port, "0123456789") || len(port) > 5 {
		return "", 0, bad
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, bad
	}
	return host, n, nil
}

// badURLChars refuses bytes that URL parsers disagree about: controls,
// space, DEL, backslash and non-ASCII. The WHATWG parser silently strips
// tab and newline and treats "\" as "/"; a strict parser does not. Refusing
// them removes the disagreement.
func badURLChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			return true
		}
	}
	return false
}

// hasScheme reports whether s starts with "scheme:" (RFC 3986 §3.1:
// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":").
func hasScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		case i > 0 && c == ':':
			return true
		default:
			return false
		}
	}
	return false
}

func stripFragment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[:i]
	}
	return s
}

// resolvePath resolves a relative reference (no scheme, no authority)
// against the base request path, per RFC 3986 §5.2.2: "?q" keeps the base
// path, "/x" replaces it, "x" replaces its last segment; then dot segments
// are removed so "../" cannot climb above "/".
func resolvePath(base, ref string) string {
	basePath, _, _ := strings.Cut(base, "?")
	if basePath == "" {
		basePath = "/"
	}
	refPath, query, hasQuery := strings.Cut(ref, "?")
	if refPath == "" && !hasQuery {
		return base // "" or "#frag": the same resource, query included
	}
	var p string
	switch {
	case refPath == "":
		p = basePath
	case strings.HasPrefix(refPath, "/"):
		p = removeDotSegments(refPath)
	default:
		p = removeDotSegments(basePath[:strings.LastIndex(basePath, "/")+1] + refPath)
	}
	if hasQuery {
		p += "?" + query
	}
	return p
}

// removeDotSegments is RFC 3986 §5.2.4 for an absolute path.
func removeDotSegments(p string) string {
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for i, seg := range segs {
		last := i == len(segs)-1
		switch seg {
		case ".":
			if last {
				out = append(out, "")
			}
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, seg)
		}
	}
	r := strings.Join(out, "/")
	if !strings.HasPrefix(r, "/") {
		r = "/" + r
	}
	return r
}
