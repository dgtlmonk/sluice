package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgtlmonk/sluice/internal/engine"
	"github.com/dgtlmonk/sluice/internal/live"
	"github.com/dgtlmonk/sluice/internal/synth"
)

// envProxyAddr overrides the proxy listen address (default engine.DefaultListenAddr).
// The engine still refuses anything that is not loopback.
const envProxyAddr = "SLUICE_PROXY_ADDR"

const proxyShutdownGrace = 3 * time.Second

// ProxyStatus is what the UI shows about the proxy listener. Exactly one of
// Addr (listening) or Error (not listening) is set once the bridge has started.
type ProxyStatus struct {
	Listening bool   `json:"listening"`
	Addr      string `json:"addr,omitempty"`
	Error     string `json:"error,omitempty"`
}

// proxyBridge owns the engine proxy server inside the app and turns engine
// Exchange events into History grid rows. It has no Wails dependency: the
// app injects emit/onStatus, which keeps it testable without a webview.
type proxyBridge struct {
	addr  string
	feed  *live.Feed[engine.Exchange]
	newID func() int64 // shared with the synthetic source so row ids never collide

	mu      sync.Mutex
	status  ProxyStatus
	srv     *engine.Server
	served  chan struct{} // closed when Serve returns
	flushed chan struct{} // closed when the feed flusher returns
	// summaries keeps one line per engine row so the detail pane has
	// something real to show until storage lands. Grows with history; see
	// SPEC.md optimization backlog.
	summaries map[int64]synth.Detail
}

func newProxyBridge(addr string, newID func() int64) *proxyBridge {
	return &proxyBridge{
		addr:      addr,
		feed:      live.NewFeed[engine.Exchange](liveQueueCapacity, liveMaxBatch),
		newID:     newID,
		summaries: map[int64]synth.Detail{},
	}
}

// proxyAddrFromEnv returns the configured listen address.
func proxyAddrFromEnv() string {
	if v := strings.TrimSpace(os.Getenv(envProxyAddr)); v != "" {
		return v
	}
	return engine.DefaultListenAddr
}

// start opens the listener and begins serving. A listen failure (port taken,
// non-loopback address) is not fatal: it becomes the status, and the app keeps
// running so the user can see why. emit receives row batches; it must not block
// for long, since a slow emit only makes the lossy feed drop.
func (b *proxyBridge) start(ctx context.Context, emit func([]synth.Exchange)) ProxyStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.flushed = make(chan struct{})
	go func() {
		defer close(b.flushed)
		b.feed.Run(ctx, flushInterval, func(batch []engine.Exchange) {
			emit(b.toRows(batch))
		})
	}()

	ln, err := engine.Listen(b.addr, false)
	if err != nil {
		b.status = ProxyStatus{Error: listenReason(b.addr, err)}
		return b.status
	}

	cfg := engine.DefaultConfig()
	cfg.Events = b.feed
	b.srv = engine.NewServer(cfg)
	b.served = make(chan struct{})
	srv := b.srv
	go func() {
		defer close(b.served)
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, engine.ErrServerClosed) {
			b.setStatus(ProxyStatus{Error: "proxy stopped: " + err.Error()})
		}
	}()
	b.status = ProxyStatus{Listening: true, Addr: ln.Addr().String()}
	return b.status
}

// listenReason turns a listen error into a short human reason.
func listenReason(addr string, err error) string {
	switch {
	case errors.Is(err, engine.ErrNonLoopback):
		return fmt.Sprintf("%s is not a loopback address", addr)
	case isAddrInUse(err):
		return fmt.Sprintf("%s is already in use by another program (set %s to pick another port)", addr, envProxyAddr)
	default:
		return err.Error()
	}
}

func isAddrInUse(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && strings.Contains(strings.ToLower(op.Err.Error()), "address already in use")
}

func (b *proxyBridge) setStatus(s ProxyStatus) {
	b.mu.Lock()
	b.status = s
	b.mu.Unlock()
}

func (b *proxyBridge) Status() ProxyStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status
}

// stop shuts the server down gracefully (in-flight exchanges get a grace
// period) and waits for the flusher, whose ctx the caller has cancelled.
func (b *proxyBridge) stop() {
	b.mu.Lock()
	srv, served, flushed := b.srv, b.served, b.flushed
	b.srv = nil
	b.mu.Unlock()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), proxyShutdownGrace)
		_ = srv.Shutdown(ctx)
		cancel()
		<-served
	}
	if flushed != nil {
		<-flushed
	}
}

// detail returns the summary detail for an engine row, if it is one.
func (b *proxyBridge) detail(id int64) (synth.Detail, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.summaries[id]
	return d, ok
}

// toRows maps engine exchanges onto the grid row shape. The engine carries
// no headers yet, so MIME stays empty and the LLM flag is false (M2 adds it).
func (b *proxyBridge) toRows(batch []engine.Exchange) []synth.Exchange {
	rows := make([]synth.Exchange, len(batch))
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, ex := range batch {
		host, port := splitHostPort(ex.Host)
		row := synth.Exchange{
			ID:         b.newID(),
			StartedAt:  ex.Started.UnixMilli(),
			Method:     ex.Method,
			Scheme:     "http", // M1 proxies plain HTTP only
			Host:       host,
			Port:       port,
			Path:       ex.Path,
			Status:     ex.Status,
			ReqSize:    int(ex.ReqBytes),
			RespSize:   int(ex.RespBytes),
			DurationMs: int(ex.Duration.Milliseconds()),
		}
		rows[i] = row
		b.summaries[row.ID] = summarize(row.ID, ex)
	}
	return rows
}

// summarize builds the placeholder detail text. Exchange holds no headers or
// bodies, so this never contains secrets.
func summarize(id int64, ex engine.Exchange) synth.Detail {
	req := fmt.Sprintf("%s http://%s%s\n\n(raw request capture arrives with storage)", ex.Method, ex.Host, ex.Path)
	resp := fmt.Sprintf("status %d · %d B in %s", ex.Status, ex.RespBytes, ex.Duration.Round(time.Millisecond))
	if ex.Err != "" {
		resp += "\nproxy error: " + ex.Err
	}
	return synth.Detail{ID: id, Request: req, Response: resp}
}

// splitHostPort splits an authority; a missing port means the http default.
func splitHostPort(authority string) (string, int) {
	host, p, err := net.SplitHostPort(authority)
	if err != nil {
		return authority, 80
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return host, 80
	}
	return host, port
}
