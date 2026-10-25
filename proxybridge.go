package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgtlmonk/sluice/internal/detect"
	"github.com/dgtlmonk/sluice/internal/engine"
	"github.com/dgtlmonk/sluice/internal/live"
	"github.com/dgtlmonk/sluice/internal/storage"
	"github.com/dgtlmonk/sluice/internal/synth"
)

// envProxyAddr overrides the proxy listen address (default engine.DefaultListenAddr).
// The engine still refuses anything that is not loopback.
const envProxyAddr = "SLUICE_PROXY_ADDR"

const proxyShutdownGrace = 3 * time.Second

// storageDrainTimeout bounds how long shutdown waits for queued history rows.
const storageDrainTimeout = 10 * time.Second

// ProxyStatus is what the UI shows about the proxy listener. Exactly one of
// Addr (listening) or Error (not listening) is set once the bridge has started.
type ProxyStatus struct {
	Listening bool   `json:"listening"`
	Addr      string `json:"addr,omitempty"`
	Error     string `json:"error,omitempty"`
}

// historyStore is the part of the project store the bridge needs.
// *storage.Store implements it; tests substitute stalled or failing stores.
type historyStore interface {
	storage.Inserter
	GetExchange(ctx context.Context, id int64) (storage.Exchange, error)
}

// StorageStats is the storage half of the status bar: whether a project
// store is open, and the lossless writer's counters.
type StorageStats struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"` // why no store is open
	storage.WriterStats
}

// proxyBridge owns the engine proxy server inside the app. For every
// finished exchange it does two things, on two paths (SPEC.md, Architecture):
//
//   - live (lossy): a grid row goes onto feed; if the UI is slow, rows drop
//     and are counted, and the grid can re-read them from the store.
//   - storage (lossless): the full capture (raw heads + bodies) goes to the
//     single storage writer, which never blocks forwarding and reports every
//     row it fails to save.
//
// It has no Wails dependency: the app injects emit/onStorageError, which
// keeps it testable without a webview.
type proxyBridge struct {
	addr  string
	feed  *live.Feed[synth.Exchange]
	newID func() int64 // shared with the synthetic source so row ids never collide

	capture *storage.Capture
	// drainTimeout bounds how long stop waits for queued history rows.
	drainTimeout time.Duration

	mu       sync.Mutex
	status   ProxyStatus
	store    historyStore // nil when no project store could be opened
	storeErr string       // why store is nil
	writer   *storage.Writer
	srv      *engine.Server
	leaf     engine.LeafMinter // nil: HTTPS interception off (no CA)
	bypass   []string          // normalized bypass patterns; applied at start and live
	trusted  func() bool       // CA trust result for pinning detection; nil: unknown
	tlsMeta  tlsMetaIndex      // JA4 / tunnel facts per row id (not in the store yet)
	served   chan struct{}     // closed when Serve returns
	flushed  chan struct{}     // closed when the feed flusher returns
	writing  chan struct{}     // closed when the storage writer returns
	reported chan struct{}     // closed when the storage error forwarder returns
}

func newProxyBridge(addr string, newID func() int64) *proxyBridge {
	return &proxyBridge{
		addr:         addr,
		feed:         live.NewFeed[synth.Exchange](liveQueueCapacity, liveMaxBatch),
		newID:        newID,
		capture:      storage.NewCapture(storage.MaxStoredBody),
		drainTimeout: storageDrainTimeout,
		storeErr:     "no project store opened",
	}
}

// useStore sets where history is written. Call before start. A nil store
// with a reason keeps the proxy working while every exchange is counted
// (and reported) as not saved.
func (b *proxyBridge) useStore(store historyStore, unavailable string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.store, b.storeErr = store, unavailable
}

// unavailableStore is the inserter used when no project store is open: it
// fails every batch with the reason, so the writer counts and reports each
// exchange as unsaved instead of history silently being empty.
type unavailableStore struct{ reason string }

func (u unavailableStore) InsertBatch(context.Context, []storage.Exchange) error {
	return errors.New("no project store: " + u.reason)
}

// useLeafCerts turns on HTTPS interception with the loaded root CA. Call
// before start.
func (b *proxyBridge) useLeafCerts(m engine.LeafMinter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.leaf = m
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
// for long, since a slow emit only makes the lossy feed drop. onStorageError
// receives storage failures (lossy notifications; the counters in
// storageStats are the record).
func (b *proxyBridge) start(ctx context.Context, emit func([]synth.Exchange), onStorageError func(string)) ProxyStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.flushed = make(chan struct{})
	go func() {
		defer close(b.flushed)
		b.feed.Run(ctx, flushInterval, emit)
	}()

	var ins storage.Inserter = unavailableStore{reason: b.storeErr}
	if b.store != nil {
		ins = b.store
	}
	b.writer = storage.NewWriter(ins, storage.DefaultWriterConfig())
	b.writing = make(chan struct{})
	w := b.writer
	// The writer gets its own context, not ctx: ctx is cancelled at
	// shutdown, and queued rows must still be written after that. stop()
	// ends the writer with Close, which drains the queue first.
	go func() { //nolint:gosec // G118: deliberate, see the comment above
		defer close(b.writing)
		w.Run(context.Background())
	}()
	// The forwarder outlives ctx on purpose: rows are still written (and can
	// still fail) while stop drains the queue, after the UI context is gone.
	// Those late errors are logged instead of dropped. It stops once the
	// writer has returned and every pending notification is read.
	b.reported = make(chan struct{})
	go func() {
		defer close(b.reported)
		forward := func(err error) {
			if ctx.Err() != nil {
				// Shutting down: no UI left. Writer errors carry ids, counts
				// and the database's reason, never headers or bodies.
				log.Printf("storage: %v", err)
				return
			}
			onStorageError(err.Error())
		}
		for {
			select {
			case err := <-w.Errors():
				forward(err)
			case <-w.Done():
				for {
					select {
					case err := <-w.Errors():
						forward(err)
					default:
						return
					}
				}
			}
		}
	}()

	ln, err := engine.Listen(b.addr, false)
	if err != nil {
		b.status = ProxyStatus{Error: listenReason(b.addr, err)}
		return b.status
	}

	cfg := engine.DefaultConfig()
	cfg.HeadTap = func(id uint64, dir engine.Direction, raw []byte) {
		b.capture.Head(id, dir == engine.DirResponse, raw)
	}
	cfg.BodyTap = func(id uint64, dir engine.Direction, raw []byte) {
		b.capture.Body(id, dir == engine.DirResponse, raw)
	}
	cfg.Done = b.complete
	cfg.LeafCerts = b.leaf
	cfg.BypassHosts = b.bypass
	cfg.CATrusted = b.trusted
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

// complete runs on the connection goroutine when an exchange finishes. Both
// sends are non-blocking: Publish drops when the UI lags, Enqueue only
// appends to the in-memory storage queue.
func (b *proxyBridge) complete(ex engine.Exchange) {
	req, resp := b.capture.Finish(ex.ID)
	scheme := ex.Scheme
	if scheme == "" {
		scheme = "http" // a parse error before the scheme was known
	}
	host, port := splitHostPort(ex.Host, scheme)
	llmReason := detectLLM(ex.Path, req, resp)
	id := b.newID()
	if facts, ok := tlsFacts(ex); ok {
		b.mu.Lock()
		b.tlsMeta.put(id, facts)
		b.mu.Unlock()
	}
	b.feed.Publish(synth.Exchange{
		ID:         id,
		StartedAt:  ex.Started.UnixMilli(),
		Method:     ex.Method,
		Scheme:     scheme,
		Host:       host,
		Port:       port,
		Path:       ex.Path,
		Status:     ex.Status,
		ReqSize:    int(ex.ReqBytes),
		RespSize:   int(ex.RespBytes),
		DurationMs: int(ex.Duration.Milliseconds()),
		IsLLM:      llmReason != "",
		LLMReason:  llmReason,
	})
	b.mu.Lock()
	w := b.writer
	b.mu.Unlock()
	w.Enqueue(storage.Exchange{
		ID:        id,
		StartedAt: ex.Started,
		Duration:  ex.Duration,
		Scheme:    scheme,
		Host:      host,
		Port:      port,
		Method:    ex.Method,
		Path:      ex.Path,
		Status:    ex.Status,
		ReqSize:   ex.ReqBytes,
		RespSize:  ex.RespBytes,
		Err:       ex.Err,
		Tool:      "proxy",
		IsLLM:     llmReason != "",
		LLMReason: llmReason,
		Request:   req,
		Response:  resp,
	})
}

// detectLLM runs the passive LLM detector over the captured messages. It
// runs on the connection goroutine after the exchange has been forwarded,
// so it can delay the next request on that connection but never the bytes
// already sent. It is bounded (detect.MaxJSONBody) and cannot fail.
func detectLLM(path string, req, resp *storage.Message) string {
	in := detect.Input{Path: path}
	if req != nil {
		in.ReqHead, in.ReqBody, in.ReqBodyCut = req.RawHeaders, req.RawBody, req.BodyTruncated
	}
	if resp != nil {
		in.RespHead = resp.RawHeaders
	}
	return detect.LLM(in)
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
// period), then drains the storage writer, and waits for the flusher, whose
// ctx the caller has cancelled. Rows the writer could not drain in time are
// returned as an error: at shutdown there is no UI left to show it. When
// stop returns the writer has exited, so the store is safe to close.
func (b *proxyBridge) stop() error {
	b.mu.Lock()
	srv, served, flushed, w, writing, reported := b.srv, b.served, b.flushed, b.writer, b.writing, b.reported
	b.srv = nil
	b.mu.Unlock()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), proxyShutdownGrace)
		_ = srv.Shutdown(ctx)
		cancel()
		<-served
	}
	var err error
	if w != nil {
		// After Shutdown no exchange can complete any more, so nothing is
		// enqueued after Close and nothing is refused as "closed". Close
		// returns only once the writer is out of InsertBatch (on a timeout
		// it cancels the insert and counts the leftover rows as unsaved), so
		// the caller may close the store afterwards.
		err = w.Close(b.drainTimeout)
		<-writing
		<-reported
	}
	if flushed != nil {
		<-flushed
	}
	return err
}

// storageStats reports the storage path for the status bar.
func (b *proxyBridge) storageStats() StorageStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := StorageStats{Available: b.store != nil}
	if b.store == nil {
		st.Error = b.storeErr
	}
	if b.writer != nil {
		st.WriterStats = b.writer.Stats()
	}
	return st
}

// detail reads one exchange (metadata and raw messages) from the store.
// found is false when the id is not in the store (a synthetic row, or one
// the writer has not committed yet).
func (b *proxyBridge) detail(ctx context.Context, id int64) (ex storage.Exchange, found bool, err error) {
	b.mu.Lock()
	store := b.store
	b.mu.Unlock()
	if store == nil {
		return storage.Exchange{}, false, nil
	}
	ex, err = store.GetExchange(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		return storage.Exchange{}, false, nil
	}
	if err != nil {
		return storage.Exchange{}, false, err
	}
	return ex, true, nil
}

// rowFromStored maps a stored exchange onto the grid row shape.
func rowFromStored(ex storage.Exchange) synth.Exchange {
	return synth.Exchange{
		ID:         ex.ID,
		StartedAt:  ex.StartedAt.UnixMilli(),
		Method:     ex.Method,
		Scheme:     ex.Scheme,
		Host:       ex.Host,
		Port:       ex.Port,
		Path:       ex.Path,
		Status:     ex.Status,
		ReqSize:    int(ex.ReqSize),
		RespSize:   int(ex.RespSize),
		DurationMs: int(ex.Duration.Milliseconds()),
		IsLLM:      ex.IsLLM,
		LLMReason:  ex.LLMReason,
	}
}

// splitHostPort splits an authority; a missing port means the scheme's
// default (443 for https, 80 otherwise).
func splitHostPort(authority, scheme string) (string, int) {
	def := 80
	if scheme == "https" {
		def = 443
	}
	host, p, err := net.SplitHostPort(authority)
	if err != nil {
		return strings.Trim(authority, "[]"), def
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return host, def
	}
	return host, port
}

// ExchangeTLS is what the detail pane shows about a row's TLS client.
type ExchangeTLS struct {
	JA4          string `json:"ja4,omitempty"`
	Tunnel       string `json:"tunnel,omitempty"` // why it was tunnelled raw; "" when decrypted
	PinSuspected bool   `json:"pinSuspected,omitempty"`
	// Unused: a CONNECT the client closed without using (browser
	// preconnect). The row's proxy error is then a note, shown muted.
	Unused bool `json:"unused,omitempty"`
}

// tlsFacts picks the detail pane's TLS facts out of an exchange; ok is false
// for a plain HTTP row with nothing to show.
func tlsFacts(ex engine.Exchange) (ExchangeTLS, bool) {
	f := ExchangeTLS{JA4: ex.JA4, Tunnel: ex.Tunnel, PinSuspected: ex.PinSuspected, Unused: ex.Unused}
	return f, f != ExchangeTLS{}
}

// TLSHost is a host the engine tunnels raw on its own (Settings list).
type TLSHost struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
	Since  string `json:"since"` // RFC 3339
}

// maxTLSMeta bounds tlsMetaIndex. The store has no column for these facts
// yet (schema v1), so they live in memory for this session's newest rows.
const maxTLSMeta = 100_000

// tlsMetaIndex maps row ids to TLS facts, forgetting the oldest past
// maxTLSMeta. Guarded by proxyBridge.mu.
type tlsMetaIndex struct {
	byID  map[int64]ExchangeTLS
	order []int64 // insertion order, for eviction
}

func (m *tlsMetaIndex) put(id int64, v ExchangeTLS) {
	if m.byID == nil {
		m.byID = map[int64]ExchangeTLS{}
	}
	if len(m.order) >= maxTLSMeta {
		delete(m.byID, m.order[0])
		m.order = m.order[1:]
	}
	m.byID[id] = v
	m.order = append(m.order, id)
}

// useTLSPolicy sets the initial bypass list (already normalized) and the CA
// trust callback. Call before start.
func (b *proxyBridge) useTLSPolicy(bypass []string, trusted func() bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bypass, b.trusted = bypass, trusted
}

// setBypass validates and applies a new bypass list, live if the proxy runs.
// It returns the normalized list.
func (b *proxyBridge) setBypass(patterns []string) ([]string, error) {
	norm, err := engine.NormalizeBypass(patterns)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.srv != nil {
		if err := b.srv.SetBypassHosts(norm); err != nil {
			return nil, err
		}
	}
	b.bypass = norm
	return slices.Clone(norm), nil
}

func (b *proxyBridge) bypassHosts() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.bypass)
}

func (b *proxyBridge) learnedHosts() []TLSHost {
	b.mu.Lock()
	srv := b.srv
	b.mu.Unlock()
	if srv == nil {
		return []TLSHost{}
	}
	flags := srv.LearnedHosts()
	out := make([]TLSHost, len(flags))
	for i, f := range flags {
		out[i] = TLSHost{Host: f.Host, Reason: f.Reason, Since: f.Since.Format(time.RFC3339)}
	}
	return out
}

func (b *proxyBridge) forgetHost(host string) {
	b.mu.Lock()
	srv := b.srv
	b.mu.Unlock()
	if srv != nil {
		srv.ForgetHost(host)
	}
}

func (b *proxyBridge) exchangeTLS(id int64) ExchangeTLS {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tlsMeta.byID[id]
}
