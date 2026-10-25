package engine

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParseAbsoluteTarget(t *testing.T) {
	ok := []struct{ in, auth, addr, path string }{
		{"http://example.com/a?b", "example.com", "example.com:80", "/a?b"},
		{"http://example.com", "example.com", "example.com:80", "/"},
		{"http://example.com?q", "example.com", "example.com:80", "/?q"},
		{"HTTP://h:8080/x", "h:8080", "h:8080", "/x"},
		{"http://[::1]:9/x", "[::1]:9", "[::1]:9", "/x"},
		{"http://[::1]/", "[::1]", "[::1]:80", "/"},
	}
	for _, c := range ok {
		got, err := parseAbsoluteTarget(c.in)
		if err != nil || got.authority != c.auth || got.addr != c.addr || got.path != c.path {
			t.Errorf("%q -> %+v, %v", c.in, got, err)
		}
	}
	bad := map[string]error{
		"/origin-form":         errNotAbsolute,
		"example.com:80":       errNotAbsolute,
		"https://h/":           errHTTPSTarget,
		"ftp://h/":             errBadScheme,
		"http://u:p@h/":        errBadAuthority,
		"http:///x":            errBadAuthority,
		"http://h:0/":          errBadAuthority,
		"http://h:99999/":      errBadAuthority,
		"http://h:+80/":        errBadAuthority,
		"http://h:/":           errBadAuthority,
		"http://h/#frag":       errBadAuthority,
		"http://[::1/":         errBadAuthority,
		"http://[::1]x/":       errBadAuthority,
		"http://bank.com@evil": errBadAuthority,
	}
	for in, want := range bad {
		if _, err := parseAbsoluteTarget(in); !errors.Is(err, want) {
			t.Errorf("%q: err %v, want %v", in, err, want)
		}
	}
}

func TestStripHopByHop(t *testing.T) {
	h := Headers{
		{"Host", "h"}, {"Connection", "keep-alive, X-Foo"}, {"X-Foo", "1"},
		{"Keep-Alive", "timeout=5"}, {"TE", "trailers"}, {"Trailer", "X"},
		{"Upgrade", "websocket"}, {"Proxy-Authorization", "Basic x"},
		{"Proxy-Connection", "X-Bar"}, {"X-Bar", "2"}, {"Accept", "*/*"},
	}
	got := stripHopByHop(h)
	want := Headers{{"Host", "h"}, {"Accept", "*/*"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v", got)
	}
}

func TestConnectionMayNotNameFramingFields(t *testing.T) {
	for _, v := range []string{"Content-Length", "transfer-encoding", "close, Host"} {
		if err := checkConnectionTokens(Headers{{"Connection", v}}); err == nil {
			t.Errorf("Connection: %s accepted", v)
		}
	}
	if err := checkConnectionTokens(Headers{{"Connection", "keep-alive, X-Foo"}}); err != nil {
		t.Fatal(err)
	}
}

func TestWantsKeepAlive(t *testing.T) {
	cases := []struct {
		minor int
		h     Headers
		want  bool
	}{
		{1, nil, true},
		{1, Headers{{"Connection", "close"}}, false},
		{1, Headers{{"Proxy-Connection", "Close"}}, false},
		{0, nil, false},
		{0, Headers{{"Connection", "Keep-Alive"}}, true},
	}
	for _, c := range cases {
		if got := wantsKeepAlive(c.minor, c.h); got != c.want {
			t.Errorf("%d %v: %v", c.minor, c.h, got)
		}
	}
}

// The chunked writer's output must decode back to the input with net/http's
// reference reader (via a full response parse).
func TestChunkWriterRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	_ = writeHead(w, "HTTP/1.1 200 OK", Headers{{"Transfer-Encoding", "chunked"}})
	for _, p := range []string{"abc", "", strings.Repeat("z", 300)} {
		_ = writeChunk(w, []byte(p))
	}
	_ = writeLastChunk(w, Headers{{"X-Sum", "1"}})
	_ = w.Flush()
	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "abc"+strings.Repeat("z", 300) || resp.Trailer.Get("X-Sum") != "1" {
		t.Fatalf("decoded %q trailer %v", b, resp.Trailer)
	}
}

func TestChunkedRawTapIsWireExact(t *testing.T) {
	wire := "3;ext=1\r\nabc\r\n0\r\nX-T: v\r\n\r\n"
	cr := NewChunkedReader(bufio.NewReader(strings.NewReader(wire)), DefaultLimits)
	var raw bytes.Buffer
	cr.SetRawTap(func(b []byte) { raw.Write(b) })
	if _, err := io.ReadAll(cr); err != nil {
		t.Fatal(err)
	}
	if raw.String() != wire {
		t.Fatalf("tap %q, want %q", raw.String(), wire)
	}
}

func TestPlanResponse(t *testing.T) {
	resp := func(k FramingKind) *Response {
		return &Response{Minor: 1, Framing: Framing{Kind: k}}
	}
	cases := []struct {
		name          string
		minor         int
		kind          FramingKind
		chunk, ka, up bool
	}{
		{"cl/1.1", 1, FramingContentLength, false, true, true},
		{"chunked/1.1", 1, FramingChunked, true, true, true},
		{"chunked/1.0", 0, FramingChunked, false, false, true},
		{"close/1.1", 1, FramingCloseDelimited, true, true, false},
		{"close/1.0", 0, FramingCloseDelimited, false, false, false},
	}
	for _, c := range cases {
		p := planResponse(c.minor, true, resp(c.kind))
		if p.chunkOut != c.chunk || p.clientKeepAlive != c.ka || p.upstreamReusable != c.up {
			t.Errorf("%s: %+v", c.name, p)
		}
	}
}
