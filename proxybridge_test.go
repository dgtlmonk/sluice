package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/synth"
	"github.com/dgtlmonk/sluice/internal/testorigin"
)

func newTestBridge(addr string) *proxyBridge {
	var id atomic.Int64
	return newProxyBridge(addr, func() int64 { return id.Add(1) })
}

func TestBridgeEmitsRowForProxiedRequest(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()

	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	rows := make(chan synth.Exchange, 16)
	st := b.start(ctx, func(batch []synth.Exchange) {
		for _, r := range batch {
			rows <- r
		}
	})
	defer func() { cancel(); b.stop() }()
	if !st.Listening || st.Error != "" {
		t.Fatalf("status = %+v, want listening", st)
	}
	if got := b.Status(); got != st {
		t.Fatalf("Status() = %+v, want %+v", got, st)
	}

	proxyURL, _ := url.Parse("http://" + st.Addr)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://" + origin + testorigin.PathContentLength)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != testorigin.ContentLengthBody {
		t.Fatalf("body = %q", body)
	}

	select {
	case r := <-rows:
		host, port, _ := net.SplitHostPort(origin)
		if r.ID != 1 || r.Method != "GET" || r.Scheme != "http" || r.Host != host ||
			fmt.Sprint(r.Port) != port || r.Path != testorigin.PathContentLength ||
			r.Status != 200 || r.RespSize != len(testorigin.ContentLengthBody) || r.StartedAt == 0 {
			t.Fatalf("row = %+v", r)
		}
		d, ok := b.detail(r.ID)
		if !ok || !strings.Contains(d.Request, testorigin.PathContentLength) {
			t.Fatalf("detail = %+v ok=%v", d, ok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no row emitted")
	}
}

func TestBridgePortBusyReportsError(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge(busy.Addr().String())
	st := b.start(ctx, func([]synth.Exchange) {})
	defer func() { cancel(); b.stop() }()
	if st.Listening || !strings.Contains(st.Error, "already in use") {
		t.Fatalf("status = %+v, want in-use error", st)
	}
}

func TestBridgeRefusesNonLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("0.0.0.0:0")
	st := b.start(ctx, func([]synth.Exchange) {})
	defer func() { cancel(); b.stop() }()
	if st.Listening || !strings.Contains(st.Error, "not a loopback") {
		t.Fatalf("status = %+v, want loopback refusal", st)
	}
}

// Shutdown must not hang with an idle keep-alive client attached.
func TestBridgeStopWithIdleClient(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	st := b.start(ctx, func([]synth.Exchange) {})

	c, err := net.Dial("tcp", st.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = fmt.Fprintf(c, "GET http://%s%s HTTP/1.1\r\nHost: %s\r\n\r\n", origin, testorigin.PathKeepAlive, origin)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	done := make(chan struct{})
	go func() { cancel(); b.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(proxyShutdownGrace + time.Second):
		t.Fatal("stop hung")
	}
}
