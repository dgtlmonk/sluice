package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/testorigin"
)

func mustScope(t *testing.T, patterns ...string) *Scope {
	t.Helper()
	s, err := NewScope(patterns)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNormalizeScope(t *testing.T) {
	got, err := NormalizeScope([]string{
		" LocalHost. ", "", "127.0.0.1", "*.TEST", "localhost", "[::1]", "::FFFF:10.0.0.1", "*.a-b.test.",
	})
	want := []string{"localhost", "127.0.0.1", "*.test", "::1", "10.0.0.1", "*.a-b.test"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
	if got, err := NormalizeScope(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty list: %q %v (want a non-nil empty list: saved as [], not null)", got, err)
	}
}

// Every pattern shape that is refused, each for its own reason.
func TestNormalizeScopeRejects(t *testing.T) {
	for _, p := range []string{
		"*",                               // everything: defeats the point of a scope
		"*.",                              // wildcard over nothing
		"*.*.test",                        // nested wildcard
		"a.*.test",                        // wildcard not at the start
		"*test",                           // no dot: would match "eviltest"
		"http://a.test",                   // a URL, not a host
		"a.test/path",                     // a path
		"a.test:8080",                     // ports are not part of a pattern
		"[::1]:8080",                      // same, IPv6
		"user@a.test",                     // userinfo
		"a..test",                         // empty label
		"a.test..",                        // two trailing dots
		"-a.test",                         // label starts with a hyphen
		"a b.test",                        // space
		"a%2etest",                        // percent-encoding
		"a\\b.test",                       // backslash
		"bücher.test",                     // non-ASCII: must be punycode
		"*.0.0.1",                         // wildcard over an IP
		"*.127.0.0.1",                     // same
		"127.1",                           // short IPv4 form
		"2130706433",                      // IPv4 as one decimal number
		"0x7f.0.0.1",                      // hex octet
		"0177.0.0.1",                      // octal octet
		"[a.test]",                        // brackets are for IPv6 only
		"[127.0.0.1]",                     // same: Check refuses this host too
		"fe80::1%en0",                     // IPv6 zone
		"::ffff:zz",                       // not an IP
		strings.Repeat("a", 64) + ".test", // label too long
	} {
		if _, err := NormalizeScope([]string{p}); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestScopeSetKeepsOldListOnError(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	if _, err := s.Set([]string{"ok.test", "http://bad"}); err == nil {
		t.Fatal("bad list accepted")
	}
	if !slices.Equal(s.List(), DefaultScope) {
		t.Fatalf("list changed to %q", s.List())
	}
}

// The host-matching rules against the default scope (localhost, 127.0.0.1,
// *.test), one case per edge. TestScopeDialRefusesWithoutDialling runs the
// refusals through Dial too.
var scopeHostCases = []struct {
	host string
	want error // nil: in scope
}{
	{"localhost", nil},
	{"LOCALHOST", nil},           // case
	{"localhost.", nil},          // trailing dot is the DNS root
	{"127.0.0.1", nil},           //
	{"127.0.0.1.", nil},          //
	{"::ffff:127.0.0.1", nil},    // IPv4-mapped IPv6 is the same IP
	{"[::ffff:127.0.0.1]", nil},  // bracketed
	{"a.test", nil},              // wildcard: one label
	{"A.B.Test.", nil},           // many labels, case, trailing dot
	{"test", ErrOutOfScope},      // *.test does not cover the bare TLD
	{"evil-test", ErrOutOfScope}, // suffix without the dot
	{"eviltest", ErrOutOfScope},  //
	{"a.test.evil.example", ErrOutOfScope},
	{"a.testing", ErrOutOfScope},
	{"foo.localhost", ErrOutOfScope}, // exact names have no subdomains
	{"localhost.evil.example", ErrOutOfScope},
	{"127.0.0.2", ErrOutOfScope}, // the IP is exact, not a range
	{"::1", ErrOutOfScope},       // not 127.0.0.1, not in the default list
	{"[::1]", ErrOutOfScope},     //
	{"0.0.0.0", ErrOutOfScope},   // reaches localhost on many systems; not listed
	{"169.254.169.254", ErrOutOfScope},
	{"localhost..", ErrBadTarget},   // empty label
	{"127.1", ErrBadTarget},         // ambiguous IPv4 forms
	{"2130706433", ErrBadTarget},    //
	{"0x7f000001", ErrBadTarget},    //
	{"0x7f.0.0.1", ErrBadTarget},    //
	{"0177.0.0.1", ErrBadTarget},    //
	{"127.0.0.1:80", ErrBadTarget},  // a port in the host field
	{"[::1]:80", ErrBadTarget},      //
	{"fe80::1%25en0", ErrBadTarget}, // zone
	{"127.0.0.1%00", ErrBadTarget},  //
	{"loc%61lhost", ErrBadTarget},   // percent-encoding
	{"locａlhost", ErrBadTarget},     // full-width "a": a Unicode look-alike
	{"127.0.0.1@evil.example", ErrBadTarget},
	{"evil.example#.test", ErrBadTarget},
	{"", ErrBadTarget},
}

func TestScopeCheckHost(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	for _, c := range scopeHostCases {
		_, err := s.Check(Target{Scheme: "http", Host: c.host, Port: 80})
		switch {
		case c.want == nil && err != nil:
			t.Errorf("%q refused: %v", c.host, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%q: got %v, want %v", c.host, err, c.want)
		}
	}
}

func TestScopeCheckNormalizesTarget(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	got, err := s.Check(Target{Scheme: "HTTPS", Host: "A.Test.", Port: 8443})
	if err != nil || got != (Target{Scheme: "https", Host: "a.test", Port: 8443}) {
		t.Fatalf("got %+v %v", got, err)
	}
	if got.Addr() != "a.test:8443" || !got.TLS() || got.String() != "https://a.test:8443" {
		t.Fatalf("addr %s tls %v str %s", got.Addr(), got.TLS(), got)
	}
	v6 := mustScope(t, "::1")
	got, err = v6.Check(Target{Scheme: "http", Host: "[::1]", Port: 80})
	if err != nil || got.Addr() != "[::1]:80" {
		t.Fatalf("v6: %+v %v", got, err)
	}
	for _, bad := range []Target{
		{Scheme: "ftp", Host: "localhost", Port: 21},
		{Scheme: "", Host: "localhost", Port: 80},
		{Scheme: "http", Host: "localhost", Port: 0},
		{Scheme: "http", Host: "localhost", Port: 65536},
	} {
		if _, err := s.Check(bad); !errors.Is(err, ErrBadTarget) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

// An IP pattern matches only that IP, and IPs never match wildcards; the
// default scope does not include ::1, but a list can.
func TestScopeIPPatterns(t *testing.T) {
	s := mustScope(t, "::1", "10.0.0.1", "*.internal.test")
	in := []string{"::1", "[::1]", "0:0:0:0:0:0:0:1", "10.0.0.1", "::ffff:10.0.0.1", "db.internal.test"}
	out := []string{"::2", "10.0.0.10", "127.0.0.1", "localhost", "internal.test"}
	for _, h := range in {
		if _, err := s.Check(Target{Scheme: "http", Host: h, Port: 80}); err != nil {
			t.Errorf("%q refused: %v", h, err)
		}
	}
	for _, h := range out {
		if _, err := s.Check(Target{Scheme: "http", Host: h, Port: 80}); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("%q: %v", h, err)
		}
	}
}

func TestScopeEmptyListRefusesEverything(t *testing.T) {
	s := mustScope(t)
	if _, err := s.Check(Target{Scheme: "http", Host: "localhost", Port: 80}); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("empty scope allowed localhost: %v", err)
	}
}

func TestScopeCheckURL(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	for _, c := range []struct {
		url, want, path string
	}{
		{"http://localhost/", "http://localhost:80", "/"},
		{"http://localhost", "http://localhost:80", "/"},
		{"https://a.test", "https://a.test:443", "/"},
		{"HTTP://LOCALHOST:8080/a?b=1#frag", "http://localhost:8080", "/a?b=1"},
		{"http://127.0.0.1:65535?q", "http://127.0.0.1:65535", "/?q"},
		{"http://[::ffff:127.0.0.1]:81/x", "http://127.0.0.1:81", "/x"},
		{"https://a.test./", "https://a.test:443", "/"},
		// The fragment ends the authority: this URL's host is localhost.
		{"http://localhost#@evil.example/", "http://localhost:80", "/"},
	} {
		got, path, err := s.CheckURL(c.url)
		if err != nil || got.String() != c.want || path != c.path {
			t.Errorf("%s: got %s %q %v; want %s %q", c.url, got, path, err, c.want, c.path)
		}
	}
}

// Every URL trick that must not get an out-of-scope host past the check
// (default scope).
var scopeURLRejects = []struct {
	url  string
	want error
}{
	// Userinfo: the real host is after the "@".
	{"http://127.0.0.1@evil.example/", ErrBadTarget},
	{"http://localhost:80@evil.example/", ErrBadTarget},
	{"http://user:pass@localhost/", ErrBadTarget}, // refused even when in scope
	{"http://a.test%40evil.example/", ErrBadTarget},
	// Fragment and query end the authority, so these hosts are evil.
	{"http://evil.example#@localhost/", ErrOutOfScope},
	{"http://evil.example?@localhost/", ErrOutOfScope},
	{"http://evil.example/@localhost", ErrOutOfScope},
	// Backslash: WHATWG reads "\" as "/", making evil.example the host.
	{"http://evil.example\\@localhost/", ErrBadTarget},
	{"http://localhost\\.evil.example/", ErrBadTarget},
	// Whitespace and controls that some parsers strip.
	{"http://local\thost/", ErrBadTarget},
	{"http://localhost\n.evil.example/", ErrBadTarget},
	{" http://localhost/", ErrBadTarget},
	// Suffix look-alikes.
	{"http://evil-test/", ErrOutOfScope},
	{"http://a.test.evil.example/", ErrOutOfScope},
	{"http://localhost.evil.example/", ErrOutOfScope},
	// Alternative IPv4 spellings of 127.0.0.1 and friends.
	{"http://2130706433/", ErrBadTarget},
	{"http://0x7f.1/", ErrBadTarget},
	{"http://127.1/", ErrBadTarget},
	{"http://0177.0.0.1/", ErrBadTarget},
	// Ports.
	{"http://localhost:0/", ErrBadTarget},
	{"http://localhost:65536/", ErrBadTarget},
	{"http://localhost:/", ErrBadTarget},
	{"http://localhost:+80/", ErrBadTarget},
	{"http://localhost:8o/", ErrBadTarget},
	{"http://localhost:80:80/", ErrBadTarget},
	// IPv6.
	{"http://::1/", ErrBadTarget},             // unbracketed
	{"http://[::1/", ErrBadTarget},            // unclosed
	{"http://[::1]x/", ErrBadTarget},          // junk after ]
	{"http://[::1]/", ErrOutOfScope},          // well-formed, not listed
	{"http://[fe80::1%25en0]/", ErrBadTarget}, // zone
	{"http://[127.0.0.1]/", ErrBadTarget},     // IPv4 in brackets
	{"http://[::ffff:169.254.169.254]/", ErrOutOfScope},
	// Schemes.
	{"gopher://localhost/", ErrBadTarget},
	{"file:///etc/passwd", ErrBadTarget},
	{"ftp://localhost/", ErrBadTarget},
	{"http:/localhost/", ErrBadTarget},
	{"http:localhost", ErrBadTarget},
	{"//localhost/", ErrBadTarget},
	{"localhost:80", ErrBadTarget},
	{"https:///", ErrBadTarget},
	{"", ErrBadTarget},
	// Non-ASCII and percent-encoding in the host.
	{"http://locａlhost/", ErrBadTarget},
	{"http://loc%61lhost/", ErrBadTarget},
}

func TestScopeCheckURLRejects(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	for _, c := range scopeURLRejects {
		got, path, err := s.CheckURL(c.url)
		if !errors.Is(err, c.want) {
			t.Errorf("%q: got %v, want %v", c.url, err, c.want)
		}
		// A refusal hands back nothing a careless caller could still use.
		if got != (Target{}) || path != "" {
			t.Errorf("%q: refused but returned %+v %q", c.url, got, path)
		}
	}
}

// A refusal must not echo credentials from the URL into an error (and so a
// log): CLAUDE.md, never log auth.
func TestScopeErrorsDoNotEchoURL(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	for _, u := range []string{
		"http://admin:hunter2@localhost/",
		"http://evil.example/?token=hunter2",
		"http://hunter2.example/",
	} {
		_, _, err := s.CheckURL(u)
		if err == nil {
			t.Fatalf("%q accepted", u)
		}
		if strings.Contains(err.Error(), "hunter2") && !strings.Contains(u, "hunter2.example") {
			t.Errorf("%q: error leaks the secret: %v", u, err)
		}
		if strings.Contains(err.Error(), "token=") || strings.Contains(err.Error(), "admin") {
			t.Errorf("%q: error echoes the URL: %v", u, err)
		}
	}
}

func TestScopeRedirect(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	from := Target{Scheme: "https", Host: "a.test", Port: 8443}
	for _, c := range []struct {
		loc, want, path string
	}{
		{"/next", "https://a.test:8443", "/next"},
		{"next", "https://a.test:8443", "/dir/next"},
		{"../up?x=1", "https://a.test:8443", "/up?x=1"},
		{"../../../../etc", "https://a.test:8443", "/etc"},
		{"./same#frag", "https://a.test:8443", "/dir/same"},
		{"?q=2", "https://a.test:8443", "/dir/page?q=2"},
		{"#top", "https://a.test:8443", "/dir/page?old=1"},
		{"//b.test/x", "https://b.test:443", "/x"},
		{"http://localhost:8080/y", "http://localhost:8080", "/y"},
		{"  /trimmed  ", "https://a.test:8443", "/trimmed"},
	} {
		got, path, err := s.Redirect(from, "/dir/page?old=1", c.loc)
		if err != nil || got.String() != c.want || path != c.path {
			t.Errorf("%q: got %s %q %v; want %s %q", c.loc, got, path, err, c.want, c.path)
		}
	}
}

// Every redirect hop that must not be followed (default scope, from
// http://localhost:80/).
var scopeRedirectRejects = []struct {
	loc  string
	want error
}{
	{"http://169.254.169.254/latest/meta-data/", ErrOutOfScope}, // cloud metadata
	{"http://evil.example/", ErrOutOfScope},
	{"//evil.example/", ErrOutOfScope},               // scheme-relative
	{"https://evil-test/", ErrOutOfScope},            //
	{"http://[::1]/", ErrOutOfScope},                 //
	{"http://0.0.0.0:8080/", ErrOutOfScope},          //
	{"http://127.0.0.1@evil.example/", ErrBadTarget}, // userinfo
	{"/\\evil.example/", ErrBadTarget},               // browsers: host evil.example
	{"\\\\evil.example/", ErrBadTarget},              //
	{"http:\\\\evil.example", ErrBadTarget},          //
	{"///evil.example/", ErrBadTarget},               // empty authority
	{"http:evil.example", ErrBadTarget},              // WHATWG: host evil.example
	{"http:/evil.example", ErrBadTarget},             //
	{"gopher://localhost:6379/_FLUSHALL", ErrBadTarget},
	{"javascript:alert(1)", ErrBadTarget},
	{"data:text/html,x", ErrBadTarget},
	{"localhost:8080/x", ErrBadTarget}, // RFC 3986: "localhost:" is a scheme
	{"http://2130706433/", ErrBadTarget},
	{"/a\r\nSet-Cookie: x", ErrBadTarget},
	{"", ErrBadTarget},
}

func TestScopeRedirectRejects(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	from := Target{Scheme: "http", Host: "localhost", Port: 80}
	for _, c := range scopeRedirectRejects {
		_, _, err := s.Redirect(from, "/", c.loc)
		if !errors.Is(err, c.want) {
			t.Errorf("%q: got %v, want %v", c.loc, err, c.want)
		}
	}
}

// A relative hop re-checks the origin: if the scope changed between hops,
// the next hop is refused even though it stays on the same host.
func TestScopeRedirectRechecksSameOrigin(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	from := Target{Scheme: "http", Host: "a.test", Port: 80}
	if _, err := s.Set([]string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Redirect(from, "/", "/next"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("same-origin hop after scope change: %v", err)
	}
}

func TestRemoveDotSegments(t *testing.T) {
	for in, want := range map[string]string{
		"/a/b/c/./../../g": "/a/g", // RFC 3986 §5.2.4 example
		"/../x":            "/x",
		"/a/..":            "/",
		"/a/.":             "/a/",
		"/a//b":            "/a//b",
		"/":                "/",
	} {
		if got := removeDotSegments(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

// --- Integration: Dial and Redirect against internal/testorigin. ---

// countingDial wraps the real dialer and counts every attempt, so a test
// can prove a refused target never reached the network (not even DNS).
func countingDial(s *Scope) *atomic.Int32 {
	var n atomic.Int32
	real := s.dial
	s.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		n.Add(1)
		return real(ctx, network, addr)
	}
	return &n
}

// get sends one GET over c and returns the parsed response head.
func scopeGet(t *testing.T, c net.Conn, path string) *Response {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", path); err != nil {
		t.Fatal(err)
	}
	resp, err := ReadResponse(bufio.NewReader(c), DefaultLimits, "GET")
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func originTarget(t *testing.T, addr string) Target {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	return Target{Scheme: "http", Host: "127.0.0.1", Port: port}
}

func TestScopeDialInScopeReachesOrigin(t *testing.T) {
	addr, stop := testorigin.Start()
	defer stop()
	s := mustScope(t, DefaultScope...)
	dials := countingDial(s)

	for _, host := range []string{"127.0.0.1", "127.0.0.1.", "[::ffff:127.0.0.1]"} {
		tgt := originTarget(t, addr)
		tgt.Host = host
		c, got, err := s.Dial(context.Background(), tgt)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got.Host != "127.0.0.1" {
			t.Errorf("%s dialled as %q", host, got.Host)
		}
		resp := scopeGet(t, c, testorigin.PathContentLength)
		_ = c.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", host, resp.StatusCode)
		}
	}
	if dials.Load() != 3 {
		t.Fatalf("%d dials", dials.Load())
	}
}

func TestScopeDialRefusesWithoutDialling(t *testing.T) {
	addr, stop := testorigin.Start()
	defer stop()
	tgt := originTarget(t, addr)
	// The origin listens on 127.0.0.1, but the scope does not list it:
	// a literal IP is checked like any host.
	s := mustScope(t, "localhost", "*.test")
	dials := countingDial(s)

	for _, host := range []string{"127.0.0.1", "evil.example", "2130706433", "127.0.0.1@evil.example", "[::1]"} {
		tgt.Host = host
		c, _, err := s.Dial(context.Background(), tgt)
		if err == nil {
			_ = c.Close()
			t.Fatalf("%s: dialled", host)
		}
		if !errors.Is(err, ErrOutOfScope) && !errors.Is(err, ErrBadTarget) {
			t.Fatalf("%s: %v", host, err)
		}
	}
	if dials.Load() != 0 {
		t.Fatalf("refused targets reached the dialer %d times", dials.Load())
	}
}

// Every refusal in the host, URL and redirect tables, sent straight to
// Dial: Dial must refuse it on its own (not rely on a caller having run
// Check first) and never reach the dialer, not even for DNS.
func TestScopeDialRefusesEveryRejectedTarget(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	dials := countingDial(s)
	dialRefused := func(what string, tgt Target) {
		t.Helper()
		c, _, err := s.Dial(context.Background(), tgt)
		if err == nil {
			_ = c.Close()
			t.Errorf("%s: dialled %+v", what, tgt)
			return
		}
		if !errors.Is(err, ErrOutOfScope) && !errors.Is(err, ErrBadTarget) {
			t.Errorf("%s: %v", what, err)
		}
	}
	n := 0
	for _, c := range scopeHostCases {
		if c.want != nil {
			dialRefused("host "+strconv.Quote(c.host), Target{Scheme: "http", Host: c.host, Port: 80})
			n++
		}
	}
	// URLs and redirect locations: whatever host the raw parser pulls out
	// (before any scope check) is dialled directly.
	urls := []string{}
	for _, c := range scopeURLRejects {
		urls = append(urls, c.url)
	}
	for _, c := range scopeRedirectRejects {
		if strings.HasPrefix(c.loc, "//") {
			urls = append(urls, "http:"+c.loc)
		} else {
			urls = append(urls, c.loc)
		}
	}
	for _, u := range urls {
		tgt, _, err := parseTargetURL(u)
		if err != nil {
			continue // not even parseable: nothing to dial
		}
		dialRefused("URL "+strconv.Quote(u), tgt)
		n++
	}
	if n < 40 {
		t.Fatalf("only %d targets reached Dial; the tables shrank?", n)
	}
	if dials.Load() != 0 {
		t.Fatalf("refused targets reached the dialer %d times", dials.Load())
	}
}

// Dial resolves a host name rooted ("a.test."), so the system resolver
// cannot append a DNS search domain ("a.test.lan") the check never saw.
// IPs are dialled as they are. The returned Target keeps the plain name.
func TestScopeDialSendsRootedNames(t *testing.T) {
	s := mustScope(t, "localhost", "*.test", "127.0.0.1", "::1")
	var addr string
	s.dial = func(_ context.Context, _, a string) (net.Conn, error) {
		addr = a
		return nil, errors.New("stub")
	}
	for _, c := range []struct {
		host, dialled string
	}{
		{"nothere.test", "nothere.test.:443"},
		{"A.Test.", "a.test.:443"},
		{"localhost", "localhost.:443"},
		{"127.0.0.1", "127.0.0.1:443"},
		{"127.0.0.1.", "127.0.0.1:443"},
		{"[::1]", "[::1]:443"},
		{"::ffff:127.0.0.1", "127.0.0.1:443"},
	} {
		addr = ""
		_, _, _ = s.Dial(context.Background(), Target{Scheme: "https", Host: c.host, Port: 443})
		if addr != c.dialled {
			t.Errorf("%q dialled as %q, want %q", c.host, addr, c.dialled)
		}
	}
	got, err := s.Check(Target{Scheme: "https", Host: "a.test.", Port: 443})
	if err != nil || got.Host != "a.test" || got.Addr() != "a.test:443" {
		t.Fatalf("checked target %+v %v: Host and Addr stay unrooted (Host header, SNI)", got, err)
	}
}

// The rooted name really resolves: "localhost." reaches the origin through
// the system resolver (hosts file), with no DNS traffic off the machine.
func TestScopeDialRootedLocalhostReachesOrigin(t *testing.T) {
	addr, stop := testorigin.Start()
	defer stop()
	s := mustScope(t, DefaultScope...)
	tgt := originTarget(t, addr)
	tgt.Host = "localhost"
	c, got, err := s.Dial(context.Background(), tgt)
	if err != nil {
		// localhost may resolve to ::1 first while the origin listens on
		// 127.0.0.1 only; the dialer falls back, so an error here is real.
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if got.Host != "localhost" {
		t.Errorf("target host %q", got.Host)
	}
	if resp := scopeGet(t, c, testorigin.PathContentLength); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestScopeWarnings(t *testing.T) {
	got := ScopeWarnings([]string{"localhost", "127.0.0.1", "*.test", "*.internal", "*.com", "*.example.com", "0.0.0.0", "::", "::1"})
	if len(got) != 3 {
		t.Fatalf("got %q; want warnings for *.com, 0.0.0.0 and ::", got)
	}
	for i, want := range []string{"*.com", "0.0.0.0", "::"} {
		if !strings.HasPrefix(got[i], want+" ") {
			t.Errorf("warning %d = %q, want it about %s", i, got[i], want)
		}
	}
	if w := ScopeWarnings(DefaultScope); w == nil || len(w) != 0 {
		t.Fatalf("default scope warns: %q (want a non-nil empty list)", w)
	}
}

// The origin answers 302 with a Location the test chooses; each hop goes
// through Redirect before it could be followed.
func TestScopeRedirectHopsAgainstOrigin(t *testing.T) {
	addr, stop := testorigin.Start()
	defer stop()
	s := mustScope(t, DefaultScope...)
	from := originTarget(t, addr)

	for _, c := range []struct {
		to   string
		want error // nil: the hop is allowed, and is followed
	}{
		{testorigin.PathContentLength, nil},
		{"http://" + addr + testorigin.PathContentLength, nil},
		{"http://localhost:" + strconv.Itoa(from.Port) + testorigin.PathContentLength, nil},
		{"http://169.254.169.254/latest/meta-data/", ErrOutOfScope},
		{"//evil.example/", ErrOutOfScope},
		{"http://127.0.0.1@evil.example/", ErrBadTarget},
		{"/\\evil.example/", ErrBadTarget},
		{"gopher://127.0.0.1:6379/_x", ErrBadTarget},
	} {
		c0, _, err := s.Dial(context.Background(), from)
		if err != nil {
			t.Fatal(err)
		}
		path := testorigin.PathRedirect + "?to=" + url.QueryEscape(c.to)
		resp := scopeGet(t, c0, path)
		_ = c0.Close()
		if resp.StatusCode != 302 {
			t.Fatalf("%s: status %d", c.to, resp.StatusCode)
		}
		loc := resp.Headers.Get("Location")
		if loc != c.to {
			t.Fatalf("origin sent Location %q, want %q", loc, c.to)
		}

		next, nextPath, err := s.Redirect(from, path, loc)
		if c.want != nil {
			if !errors.Is(err, c.want) {
				t.Errorf("%q: got %v, want %v", c.to, err, c.want)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q refused: %v", c.to, err)
		}
		c1, _, err := s.Dial(context.Background(), next)
		if err != nil {
			t.Fatalf("%q: %v", c.to, err)
		}
		resp = scopeGet(t, c1, nextPath)
		_ = c1.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%q: followed hop got %d", c.to, resp.StatusCode)
		}
	}
}

// Dial applies its own timeout when the caller gives none, so an active
// send to a black-holed in-scope host cannot hang forever.
func TestScopeDialHasDeadline(t *testing.T) {
	s := mustScope(t, DefaultScope...)
	var hadDeadline bool
	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		_, hadDeadline = ctx.Deadline()
		return nil, errors.New("stub")
	}
	_, _, _ = s.Dial(context.Background(), Target{Scheme: "http", Host: "localhost", Port: 1})
	if !hadDeadline {
		t.Fatal("dial ran without a deadline")
	}
}
