package engine

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/live"
	"github.com/dgtlmonk/sluice/internal/testorigin"
)

// collectEvents drains feed in the background and hands each Exchange to the returned channel.
func collectEvents(t *testing.T, feed *live.Feed[Exchange]) <-chan Exchange {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan Exchange, 64)
	go feed.Run(ctx, 5*time.Millisecond, func(b []Exchange) {
		for _, e := range b {
			out <- e
		}
	})
	return out
}

func waitEvent(t *testing.T, ch <-chan Exchange) Exchange {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
		return Exchange{}
	}
}

// echoOrigin echoes the request body and reports the Expect header it saw.
func echoOrigin(t *testing.T) *countingOrigin {
	return startCountingOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Expect", r.Header.Get("Expect"))
		w.Header().Set("X-Saw-TE", strings.Join(r.TransferEncoding, ","))
		_, _ = io.Copy(w, r.Body)
	}))
}

func TestProxyRecordsRequestBytes(t *testing.T) {
	co := echoOrigin(t)
	feed := live.NewFeed[Exchange](10, 10)
	proxy, _ := startProxy(t, Config{Events: feed})
	events := collectEvents(t, feed)
	rc := dialProxy(t, proxy)
	rc.send("POST http://" + co.addr + "/ HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\npayload-123")
	if resp, b := rc.read("POST"); resp.StatusCode != 200 || b != "payload-123" {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if e := waitEvent(t, events); e.ReqBytes != 11 {
		t.Fatalf("ReqBytes %d, want 11", e.ReqBytes)
	}
}

func TestProxyForwardsChunkedRequestBody(t *testing.T) {
	co := echoOrigin(t)
	feed := live.NewFeed[Exchange](10, 10)
	proxy, _ := startProxy(t, Config{Events: feed})
	events := collectEvents(t, feed)
	rc := dialProxy(t, proxy)
	rc.send("POST http://" + co.addr + "/ HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	resp, b := rc.read("POST")
	if resp.StatusCode != 200 || b != "hello world" {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if te := resp.Header.Get("X-Saw-TE"); te != "chunked" {
		t.Fatalf("origin saw TE %q, want chunked", te)
	}
	if e := waitEvent(t, events); e.ReqBytes != 11 {
		t.Fatalf("ReqBytes %d, want 11 (decoded)", e.ReqBytes)
	}
}

func TestProxyHEADHasNoBody(t *testing.T) {
	origin := startOrigin(t)
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	rc.send("HEAD http://" + origin + testorigin.PathContentLength + " HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, b := rc.read("HEAD")
	if resp.StatusCode != 200 || b != "" {
		t.Fatalf("HEAD: %d %q", resp.StatusCode, b)
	}
	if resp.Header.Get("Content-Length") == "" {
		t.Fatalf("HEAD lost Content-Length: %v", resp.Header)
	}
	// If the proxy had waited for (or relayed) body bytes after the HEAD
	// head, this second exchange on the same conn would be corrupted.
	rc.send(get("http://" + origin + testorigin.PathContentLength))
	if resp, b := rc.read("GET"); resp.StatusCode != 200 || b != testorigin.ContentLengthBody {
		t.Fatalf("GET after HEAD: %d %q", resp.StatusCode, b)
	}
}

func TestProxyAnswersExpect100Continue(t *testing.T) {
	co := echoOrigin(t)
	proxy, _ := startProxy(t, Config{})
	rc := dialProxy(t, proxy)
	_ = rc.conn.SetDeadline(time.Now().Add(3 * time.Second))
	rc.send("POST http://" + co.addr + "/ HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n")
	// A strict client sends nothing more until it sees 100 Continue.
	line, err := rc.br.ReadString('\n')
	if err != nil || line != "HTTP/1.1 100 Continue\r\n" {
		t.Fatalf("interim line %q err %v (deadlock?)", line, err)
	}
	if blank, _ := rc.br.ReadString('\n'); blank != "\r\n" {
		t.Fatalf("after 100: %q", blank)
	}
	rc.send("data")
	resp, b := rc.read("POST")
	if resp.StatusCode != 200 || b != "data" {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if e := resp.Header.Get("X-Saw-Expect"); e != "" {
		t.Fatalf("Expect forwarded upstream: %q", e)
	}
}

// dropSecondOrigin answers the first request on each conn and keeps it open
// (so it passes the pool health check), then reads the second request and
// closes without a response: the "origin dropped a pooled conn" race.
func dropSecondOrigin(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
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
				br := bufio.NewReader(c)
				if _, err := ReadRequest(br, DefaultLimits); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				_, _ = ReadRequest(br, DefaultLimits)
			}()
		}
	}()
	return ln.Addr().String(), &conns
}

func TestProxyStaleRetryOnlyForIdempotent(t *testing.T) {
	for _, tc := range []struct {
		method     string
		wantStatus int
		wantConns  int64
	}{
		{"GET", 200, 2},    // replayed on a fresh conn
		{"DELETE", 200, 2}, // idempotent too
		{"POST", 502, 1},   // never replayed: the origin may have acted on it
		{"PATCH", 502, 1},
	} {
		t.Run(tc.method, func(t *testing.T) {
			addr, conns := dropSecondOrigin(t)
			proxy, _ := startProxy(t, Config{})
			rc := dialProxy(t, proxy)
			rc.send(get("http://" + addr + "/"))
			rc.read("GET")
			rc.send(tc.method + " http://" + addr + "/ HTTP/1.1\r\nHost: x\r\n\r\n") // bodiless
			if resp, _ := rc.read(tc.method); resp.StatusCode != tc.wantStatus {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if n := conns.Load(); n != tc.wantConns {
				t.Fatalf("origin conns %d, want %d", n, tc.wantConns)
			}
		})
	}
}

func TestIsIdempotent(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"} {
		if !isIdempotent(m) {
			t.Errorf("%s should be idempotent", m)
		}
	}
	for _, m := range []string{"POST", "PATCH", "CONNECT", "get"} {
		if isIdempotent(m) {
			t.Errorf("%s should not be idempotent", m)
		}
	}
}

func TestProxyClientHeadTrickleTimesOut(t *testing.T) {
	proxy, _ := startProxy(t, Config{HeadReadTimeout: 300 * time.Millisecond})
	rc := dialProxy(t, proxy)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		// Slowloris: one header byte every 20ms renews any idle timeout forever.
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				if _, err := rc.conn.Write([]byte("G")); err != nil {
					return
				}
			}
		}
	}()
	start := time.Now()
	_ = rc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := rc.br.ReadByte()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("proxy kept the trickling conn open past HeadReadTimeout")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("closed after %v", d)
	}
}

func TestProxyOriginHeadTrickle504(t *testing.T) {
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
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := ReadRequest(bufio.NewReader(c), DefaultLimits); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n")
				for range 200 { // never finishes the head
					if _, err := io.WriteString(c, "X"); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
		}
	}()
	proxy, _ := startProxy(t, Config{ResponseHeaderTimeout: 300 * time.Millisecond})
	rc := dialProxy(t, proxy)
	start := time.Now()
	rc.send(get("http://" + ln.Addr().String() + "/"))
	if resp, _ := rc.read("GET"); resp.StatusCode != 504 {
		t.Fatalf("status %d, want 504", resp.StatusCode)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestListenPinsLocalhostToLoopbackIP(t *testing.T) {
	ln, err := Listen("localhost:0", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if ip := ln.Addr().(*net.TCPAddr).IP; !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("bound %v, want 127.0.0.1", ip)
	}
	if got, err := loopbackAddr("LOCALHOST:8080"); err != nil || got != "127.0.0.1:8080" {
		t.Fatalf("loopbackAddr = %q, %v", got, err)
	}
	if err := CheckLoopback("localhost.example.com:0"); !errors.Is(err, ErrNonLoopback) {
		t.Fatalf("other names must be refused, got %v", err)
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-acc
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func pooled(c net.Conn) *upstreamConn {
	tc := &timeoutConn{Conn: c}
	return &upstreamConn{key: "k", conn: tc, br: bufio.NewReader(tc), bw: bufio.NewWriter(tc)}
}

func TestPoolDiscardsDirtyConns(t *testing.T) {
	cases := map[string]func(origin net.Conn){
		"unsolicited bytes": func(o net.Conn) { _, _ = io.WriteString(o, "HTTP/1.1 200 OK\r\n") },
		"closed by origin":  func(o net.Conn) { _ = o.Close() },
	}
	for name, dirty := range cases {
		t.Run(name, func(t *testing.T) {
			c, o := tcpPair(t)
			p := newConnPool(4, time.Minute)
			p.put(pooled(c))
			dirty(o)
			time.Sleep(50 * time.Millisecond) // let the bytes / FIN arrive
			if u := p.get("k"); u != nil {
				t.Fatal("dirty idle conn was handed out")
			}
		})
	}
	t.Run("healthy conn reused", func(t *testing.T) {
		c, _ := tcpPair(t)
		p := newConnPool(4, time.Minute)
		p.put(pooled(c))
		u := p.get("k")
		if u == nil {
			t.Fatal("healthy idle conn discarded")
		}
		// The peek must leave no deadline behind.
		_, _ = io.WriteString(u.conn, "x")
	})
}

func TestProxyIgnoresUnsolicitedOriginBytes(t *testing.T) {
	// The origin appends a whole fake response after the real one. Reusing
	// that conn would hand "EVIL!" to the next client request.
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
				br := bufio.NewReader(c)
				for {
					if _, err := ReadRequest(br, DefaultLimits); err != nil {
						return
					}
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
					time.Sleep(10 * time.Millisecond)
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nEVIL!")
				}
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
		time.Sleep(50 * time.Millisecond)
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("origin conns %d, want 2", n)
	}
}

func TestProxyNoEventForEmptyClient(t *testing.T) {
	feed := live.NewFeed[Exchange](10, 10)
	proxy, _ := startProxy(t, Config{Events: feed})
	rc := dialProxy(t, proxy)
	// One byte gets past the idle peek, then EOF before any request line.
	rc.send("G")
	_ = rc.conn.(*net.TCPConn).CloseWrite()
	if _, err := rc.br.ReadByte(); err == nil {
		t.Fatal("expected the proxy to close")
	}
	c2 := dialProxy(t, proxy)
	_ = c2.conn.Close() // connect and close with nothing sent
	time.Sleep(100 * time.Millisecond)
	if st := feed.Stats(); st.Published != 0 {
		t.Fatalf("published %d events for clients that sent no request", st.Published)
	}
}
