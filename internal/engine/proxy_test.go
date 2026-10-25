package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/live"
	"github.com/dgtlmonk/sluice/internal/testorigin"
)

// startProxy runs a Server on 127.0.0.1:0 and returns its address.
func startProxy(t *testing.T, cfg Config) (string, *Server) {
	t.Helper()
	ln, err := Listen("127.0.0.1:0", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(cfg)
	done := make(chan struct{})
	go func() { _ = srv.Serve(ln); close(done) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})
	return ln.Addr().String(), srv
}

func startOrigin(t *testing.T) string {
	t.Helper()
	addr, stop := testorigin.Start()
	t.Cleanup(stop)
	return addr
}

// countingOrigin wraps the test origin and counts TCP connections and requests.
type countingOrigin struct {
	addr     string
	conns    atomic.Int64
	requests atomic.Int64
}

func startCountingOrigin(t *testing.T, h http.Handler) *countingOrigin {
	t.Helper()
	co := &countingOrigin{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		co.requests.Add(1)
		h.ServeHTTP(w, r)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			co.conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	co.addr = srv.Listener.Addr().String()
	return co
}

// rawClient is a client connection to the proxy speaking bytes directly.
type rawClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func dialProxy(t *testing.T, proxyAddr string) *rawClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return &rawClient{t: t, conn: c, br: bufio.NewReader(c)}
}

func (rc *rawClient) send(s string) {
	rc.t.Helper()
	if _, err := io.WriteString(rc.conn, s); err != nil {
		rc.t.Fatal(err)
	}
}

// respInfo is the part of a parsed response the tests check. It is copied
// out so the *http.Response (and its body) never leaves read.
type respInfo struct {
	StatusCode       int
	Header           http.Header
	Close            bool
	TransferEncoding []string
}

// read parses one response with net/http as the reference oracle and
// returns it with its full body.
func (rc *rawClient) read(method string) (respInfo, string) {
	rc.t.Helper()
	resp, err := http.ReadResponse(rc.br, &http.Request{Method: method})
	if err != nil {
		rc.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		rc.t.Fatal(err)
	}
	return respInfo{resp.StatusCode, resp.Header, resp.Close, resp.TransferEncoding}, string(b)
}

func get(target string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: ignored.example\r\n\r\n"
}

func proxiedClient(proxyAddr string) *http.Client {
	pu := &url.URL{Scheme: "http", Host: proxyAddr}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
}

func TestProxyContentLength(t *testing.T) {
	origin := startOrigin(t)
	proxy, _ := startProxy(t, Config{})
	resp, err := proxiedClient(proxy).Get("http://" + origin + testorigin.PathContentLength)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != testorigin.ContentLengthBody {
		t.Fatalf("got %d %q", resp.StatusCode, b)
	}
	if resp.ContentLength != int64(len(testorigin.ContentLengthBody)) {
		t.Fatalf("Content-Length = %d, want kept from origin", resp.ContentLength)
	}
}

func TestProxyChunkedReencoded(t *testing.T) {
	origin := startOrigin(t)
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	rc.send(get("http://" + origin + testorigin.PathChunked))
	resp, body := rc.read("GET")
	if len(resp.TransferEncoding) != 1 || resp.TransferEncoding[0] != "chunked" {
		t.Fatalf("Transfer-Encoding = %v, want chunked", resp.TransferEncoding)
	}
	if body != testorigin.ChunkedBody() {
		t.Fatalf("body %q", body)
	}
}

func TestProxyKeepAliveReusesBothLegs(t *testing.T) {
	co := startCountingOrigin(t, testorigin.Handler())
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	for i, p := range []string{testorigin.PathKeepAlive, testorigin.PathChunked, testorigin.PathKeepAlive} {
		rc.send(get("http://" + co.addr + p))
		resp, _ := rc.read("GET")
		if resp.StatusCode != 200 || resp.Close {
			t.Fatalf("request %d: status %d close=%v", i, resp.StatusCode, resp.Close)
		}
	}
	if n := co.requests.Load(); n != 3 {
		t.Fatalf("origin saw %d requests, want 3", n)
	}
	if n := co.conns.Load(); n != 1 {
		t.Fatalf("origin saw %d upstream conns, want 1 (pooled reuse)", n)
	}
}

func TestProxyCloseDelimitedToHTTP11IsChunked(t *testing.T) {
	origin := startOrigin(t)
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	rc.send(get("http://" + origin + testorigin.PathClose))
	resp, body := rc.read("GET")
	if body != testorigin.CloseBody {
		t.Fatalf("body %q", body)
	}
	if len(resp.TransferEncoding) != 1 || resp.Close {
		t.Fatalf("want chunked keep-alive, got TE=%v close=%v", resp.TransferEncoding, resp.Close)
	}
	// The client conn survives even though the upstream one was consumed.
	rc.send(get("http://" + origin + testorigin.PathKeepAlive))
	if _, b := rc.read("GET"); b != testorigin.KeepAliveBody {
		t.Fatalf("second body %q", b)
	}
}

func TestProxyCloseDelimitedToHTTP10Closes(t *testing.T) {
	origin := startOrigin(t)
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	rc.send("GET http://" + origin + testorigin.PathChunked + " HTTP/1.0\r\n\r\n")
	raw, err := io.ReadAll(rc.br) // must end: proxy closes after the body
	if err != nil {
		t.Fatal(err)
	}
	head, body, _ := strings.Cut(string(raw), "\r\n\r\n")
	if strings.Contains(strings.ToLower(head), "transfer-encoding") {
		t.Fatalf("1.0 client got chunked head:\n%s", head)
	}
	if body != testorigin.ChunkedBody() {
		t.Fatalf("body %q", body)
	}
}

func TestProxySSEStreamsIncrementally(t *testing.T) {
	origin := startOrigin(t)
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	rc.send(get("http://" + origin + testorigin.PathSSE))
	resp, err := http.ReadResponse(rc.br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	br := bufio.NewReader(resp.Body)
	var arrivals []time.Time
	for range testorigin.SSEEvents {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if _, err := br.ReadString('\n'); err != nil { // blank line ending the event
			t.Fatal(err)
		}
		arrivals = append(arrivals, time.Now())
		_ = line
	}
	// Origin spaces events SSEDelay apart. If the proxy buffered, every
	// event would land at once; streamed, the first precedes the last by
	// roughly (n-1)*SSEDelay.
	spread := arrivals[len(arrivals)-1].Sub(arrivals[0])
	if min := time.Duration(len(testorigin.SSEEvents)-2) * testorigin.SSEDelay; spread < min {
		t.Fatalf("events arrived within %v; want >= %v (buffered, not streamed)", spread, min)
	}
}

func TestProxyRejectsSmugglingBeforeOrigin(t *testing.T) {
	co := startCountingOrigin(t, testorigin.Handler())
	proxy, _ := startProxy(t, Config{})
	cases := map[string]string{
		"CL+TE": "POST http://" + co.addr + "/content-length HTTP/1.1\r\nHost: x\r\n" +
			"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n",
		"Connection names Content-Length": "POST http://" + co.addr + "/content-length HTTP/1.1\r\nHost: x\r\n" +
			"Connection: Content-Length\r\nContent-Length: 30\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n",
		"bad chunk size": "POST http://" + co.addr + "/content-length HTTP/1.1\r\nHost: x\r\n" +
			"Transfer-Encoding: chunked\r\n\r\nzz\r\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			rc := dialProxy(t, proxy)
			rc.send(raw)
			resp, _ := rc.read("POST")
			if resp.StatusCode != 400 || !resp.Close {
				t.Fatalf("got %d close=%v, want 400 + close", resp.StatusCode, resp.Close)
			}
		})
	}
	// "bad chunk size" opens an upstream conn (the head is valid) but the
	// origin never gets a complete request; none of the hidden requests land.
	if n := co.requests.Load(); n != 0 {
		t.Fatalf("origin handled %d requests, want 0", n)
	}
}

func TestProxyRejectsUnsupportedTargets(t *testing.T) {
	origin := startOrigin(t)
	proxy, _ := startProxy(t, Config{})
	cases := []struct {
		name, raw string
		want      int
	}{
		{"origin-form", "GET / HTTP/1.1\r\nHost: " + origin + "\r\n\r\n", 400},
		{"https", get("https://" + origin + "/"), 400},
		{"connect", "CONNECT " + origin + " HTTP/1.1\r\nHost: " + origin + "\r\n\r\n", 405},
		{"userinfo", get("http://u:p@" + origin + "/"), 400},
		{"version", "GET http://" + origin + "/ HTTP/2.0\r\nHost: x\r\n\r\n", 505},
		{"oversize head", "GET http://" + origin + "/ HTTP/1.1\r\nHost: x\r\nX: " + strings.Repeat("a", 70<<10) + "\r\n\r\n", 431},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := dialProxy(t, proxy)
			rc.send(tc.raw)
			method := strings.SplitN(tc.raw, " ", 2)[0]
			resp, _ := rc.read(method)
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestProxyRewritesHeadForOrigin(t *testing.T) {
	type seen struct {
		uri, host string
		h         http.Header
		body      string
	}
	got := make(chan seen, 1)
	co := startCountingOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.RequestURI, r.Host, r.Header.Clone(), string(b)}
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Origin", "1")
		_, _ = io.WriteString(w, "ok")
	}))
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	rc.send("POST http://" + co.addr + "/echo?x=1 HTTP/1.1\r\n" +
		"Host: wrong.example\r\n" +
		"Proxy-Authorization: Basic c2VjcmV0\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Connection: X-Hop\r\n" +
		"X-Hop: drop-me\r\n" +
		"X-Keep: keep-me\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	resp, body := rc.read("POST")
	s := <-got
	if s.uri != "/echo?x=1" || s.host != co.addr {
		t.Fatalf("origin saw %q Host %q; want origin-form and authority Host", s.uri, s.host)
	}
	for _, n := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Hop", "Connection"} {
		if s.h.Get(n) != "" {
			t.Errorf("hop-by-hop %s forwarded", n)
		}
	}
	if s.h.Get("X-Keep") != "keep-me" || s.body != "hello world" {
		t.Fatalf("end-to-end header/body lost: %v %q", s.h, s.body)
	}
	if body != "ok" || resp.Header.Get("Keep-Alive") != "" || resp.Header.Get("X-Origin") != "1" {
		t.Fatalf("response headers %v body %q", resp.Header, body)
	}
}

func TestProxyContentLengthRequestBody(t *testing.T) {
	co := startCountingOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	proxy, _ := startProxy(t, Config{})
	resp, err := proxiedClient(proxy).Post("http://"+co.addr+"/", "text/plain", strings.NewReader("payload-123"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if b, _ := io.ReadAll(resp.Body); string(b) != "payload-123" {
		t.Fatalf("echo %q", b)
	}
}

func TestProxyUpstreamDown502(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close() // nothing listens there now: connection refused
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	rc.send(get("http://" + dead + "/"))
	if resp, _ := rc.read("GET"); resp.StatusCode != 502 {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
}

func TestProxyUpstreamTimeout504(t *testing.T) {
	// An origin that accepts and reads but never answers.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	proxy, _ := startProxy(t, Config{ResponseHeaderTimeout: 200 * time.Millisecond})
	rc := dialProxy(t, proxy)
	start := time.Now()
	rc.send(get("http://" + ln.Addr().String() + "/"))
	if resp, _ := rc.read("GET"); resp.StatusCode != 504 {
		t.Fatalf("status %d, want 504", resp.StatusCode)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("timeout took %v", d)
	}
}

func TestProxyRetriesStalePooledConn(t *testing.T) {
	// Origin answers once per connection, then closes without saying so:
	// the pooled conn is dead the next time it is used.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var conns atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := ReadRequest(bufio.NewReader(c), DefaultLimits); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}()
		}
	}()
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	for i := range 2 {
		rc.send(get("http://" + ln.Addr().String() + "/"))
		if resp, b := rc.read("GET"); resp.StatusCode != 200 || b != "ok" {
			t.Fatalf("request %d: %d %q", i, resp.StatusCode, b)
		}
		time.Sleep(50 * time.Millisecond) // let the origin's close land
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("origin conns %d, want 2 (stale conn replaced)", n)
	}
}

func TestProxyPublishesEventsAndTapsRawBody(t *testing.T) {
	origin := startOrigin(t)
	feed := live.NewFeed[Exchange](1, 10) // capacity 1: the second event drops
	var (
		mu  sync.Mutex
		raw bytes.Buffer
	)
	tap := func(_ uint64, dir Direction, b []byte) {
		if dir == DirResponse {
			mu.Lock()
			raw.Write(b)
			mu.Unlock()
		}
	}
	proxy, _ := startProxy(t, Config{Events: feed, BodyTap: tap})
	rc := dialProxy(t, proxy)
	for range 2 {
		rc.send(get("http://" + origin + testorigin.PathChunked))
		rc.read("GET")
	}
	// The event is published after the response is flushed, so wait for it.
	deadline := time.Now().Add(2 * time.Second)
	for st := feed.Stats(); st.Published+st.Dropped < 2 && time.Now().Before(deadline); st = feed.Stats() {
		time.Sleep(5 * time.Millisecond)
	}
	st := feed.Stats()
	if st.Published != 1 || st.Dropped != 1 {
		t.Fatalf("feed stats %+v, want published=1 dropped=1", st)
	}
	mu.Lock()
	got := raw.String()
	mu.Unlock()
	// Raw tap keeps the chunk framing that the decoded body loses.
	for _, want := range []string{"a\r\nchunk-one\n\r\n", "0\r\n\r\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("raw tap %q missing %q", got, want)
		}
	}
}

func TestProxyEventFields(t *testing.T) {
	origin := startOrigin(t)
	feed := live.NewFeed[Exchange](10, 10)
	proxy, _ := startProxy(t, Config{Events: feed})
	rc := dialProxy(t, proxy)
	rc.send(get("http://" + origin + testorigin.PathContentLength + "?q=1"))
	rc.read("GET")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := make(chan Exchange, 1)
	go feed.Run(ctx, 5*time.Millisecond, func(b []Exchange) {
		select {
		case got <- b[0]:
		default:
		}
	})
	select {
	case e := <-got:
		if e.Method != "GET" || e.Host != origin || e.Path != testorigin.PathContentLength+"?q=1" ||
			e.Status != 200 || e.RespBytes != int64(len(testorigin.ContentLengthBody)) || e.Err != "" {
			t.Fatalf("event %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no event")
	}
}

func TestListenRefusesNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "[::]:0", "192.0.2.1:0", "example.com:0"} {
		if _, err := Listen(addr, false); !errors.Is(err, ErrNonLoopback) {
			t.Errorf("Listen(%q) err = %v, want ErrNonLoopback", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "localhost:0"} {
		ln, err := Listen(addr, false)
		if err != nil {
			t.Errorf("Listen(%q): %v", addr, err)
			continue
		}
		_ = ln.Close()
	}
}

func TestShutdownClosesIdleClients(t *testing.T) {
	origin := startOrigin(t)
	ln, err := Listen("127.0.0.1:0", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{})
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	rc := dialProxy(t, ln.Addr().String())
	rc.send(get("http://" + origin + testorigin.PathKeepAlive))
	rc.read("GET")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-served; !errors.Is(err, ErrServerClosed) {
		t.Fatalf("serve returned %v", err)
	}
	if _, err := rc.br.ReadByte(); err == nil {
		t.Fatal("idle client conn still open after shutdown")
	}
}

// TestProxySSEFirstEventBeforeOriginFinishes proves streaming causally, not
// by timing: the origin sends one event, then blocks until the client has
// seen it. A buffering proxy would wait for the origin to finish and the
// test would time out.
func TestProxySSEFirstEventBeforeOriginFinishes(t *testing.T) {
	const first, second = "data: tok-1\n\n", "data: tok-2\n\n"
	seen := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, first)
		w.(http.Flusher).Flush()
		select {
		case <-seen:
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			return
		}
		_, _ = io.WriteString(w, second)
	}))
	t.Cleanup(origin.Close)
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	rc.send(get(origin.URL + "/sse"))
	resp, err := http.ReadResponse(rc.br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_ = rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(first))
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("first event not delivered while origin still open: %v", err)
	}
	if string(buf) != first {
		t.Fatalf("first event %q", buf)
	}
	close(seen)
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(rest) != second {
		t.Fatalf("rest %q err %v", rest, err)
	}
}
