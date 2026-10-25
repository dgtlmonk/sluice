package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/storage"
	"github.com/dgtlmonk/sluice/internal/synth"
	"github.com/dgtlmonk/sluice/internal/testorigin"
)

func newTestBridge(addr string) *proxyBridge {
	var id atomic.Int64
	return newProxyBridge(addr, func() int64 { return id.Add(1) })
}

func noStorageErrors(string) {}

// openTestStore opens an encrypted store in a temp dir with a random key.
func openTestStore(t *testing.T) *storage.Store {
	t.Helper()
	key := make([]byte, storage.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := storage.Open(filepath.Join(t.TempDir(), "p.sluice"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBridgeEmitsRowForProxiedRequest(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()

	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	b.useStore(openTestStore(t), "")
	rows := make(chan synth.Exchange, 16)
	st := b.start(ctx, func(batch []synth.Exchange) {
		for _, r := range batch {
			rows <- r
		}
	}, noStorageErrors)
	defer func() { cancel(); _ = b.stop() }()
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
		d := viewFromStored(waitDetail(t, b, r.ID))
		if !strings.Contains(d.Request.StartLine, testorigin.PathContentLength) ||
			!strings.Contains(d.Response.Body, testorigin.ContentLengthBody) {
			t.Fatalf("detail = %+v", d)
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
	st := b.start(ctx, func([]synth.Exchange) {}, noStorageErrors)
	defer func() { cancel(); _ = b.stop() }()
	if st.Listening || !strings.Contains(st.Error, "already in use") {
		t.Fatalf("status = %+v, want in-use error", st)
	}
}

func TestBridgeRefusesNonLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("0.0.0.0:0")
	st := b.start(ctx, func([]synth.Exchange) {}, noStorageErrors)
	defer func() { cancel(); _ = b.stop() }()
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
	st := b.start(ctx, func([]synth.Exchange) {}, noStorageErrors)

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
	go func() { cancel(); _ = b.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(proxyShutdownGrace + time.Second):
		t.Fatal("stop hung")
	}
}

// waitDetail polls until the storage writer has committed id.
func waitDetail(t *testing.T, b *proxyBridge, id int64) storage.Exchange {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d, found, err := b.detail(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			return d
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("exchange %d never reached the store", id)
	return storage.Exchange{}
}

// proxyGet sends n sequential GETs through the proxy at addr, each within a
// short per-request timeout, and fails if any is slow.
func proxyGet(t *testing.T, proxyAddr, target string, n int, perRequest time.Duration) {
	t.Helper()
	pu, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Timeout: perRequest, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	defer client.CloseIdleConnections()
	for i := range n {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// Full path: proxied exchanges land in the encrypted store with raw bytes,
// and the capture map is empty afterwards (no leaked drafts).
func TestBridgePersistsRawCapture(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	store := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	b.useStore(store, "")
	st := b.start(ctx, func([]synth.Exchange) {}, noStorageErrors)

	const n = 200
	proxyGet(t, st.Addr, "http://"+origin+testorigin.PathChunked, n, 5*time.Second)
	cancel()
	if err := b.stop(); err != nil {
		t.Fatal(err)
	}
	ss := b.storageStats()
	if ss.Saved != n || ss.Failed != 0 || ss.Unsaved != 0 || ss.Queued != 0 {
		t.Fatalf("storage stats %+v", ss)
	}
	ex, err := store.GetExchange(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Request == nil || !strings.HasPrefix(string(ex.Request.RawHeaders), "GET http://"+origin+testorigin.PathChunked+" HTTP/1.1\r\n") {
		t.Fatalf("request head %+v", ex.Request)
	}
	// Raw response body keeps the origin's chunk framing.
	if ex.Response == nil || !strings.Contains(string(ex.Response.RawBody), "0\r\n\r\n") || ex.Status != 200 {
		t.Fatalf("response %+v status %d", ex.Response, ex.Status)
	}
	if b.capture.Pending() != 0 {
		t.Fatalf("%d captures leaked", b.capture.Pending())
	}
}

// chunkedReader hides its length from net/http, which then sends the body
// with Transfer-Encoding: chunked.
type chunkedReader struct{ r io.Reader }

func (c chunkedReader) Read(p []byte) (int, error) { return c.r.Read(p) }

// LLM detection runs before both paths: the live row and the stored row
// carry the same flag and reason, for each of the three rules.
func TestBridgeFlagsLLMTraffic(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	store := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	b.useStore(store, "")
	rows := make(chan synth.Exchange, 16)
	st := b.start(ctx, func(batch []synth.Exchange) {
		for _, r := range batch {
			rows <- r
		}
	}, noStorageErrors)
	defer func() { cancel(); _ = b.stop() }()

	pu, _ := url.Parse("http://" + st.Addr)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	defer client.CloseIdleConnections()
	const chat = `{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`
	base := "http://" + origin
	cases := []struct {
		name, method, target string
		body                 io.Reader
		want                 string
	}{
		{"plain", "GET", base + testorigin.PathContentLength, nil, ""},
		{"sse", "GET", base + testorigin.PathSSE, nil, "sse"},
		// The origin answers 405 to a POST here; the request still counts.
		{"json content-length", "POST", base + testorigin.PathContentLength, strings.NewReader(chat), "json"},
		{"json chunked", "POST", base + testorigin.PathContentLength, chunkedReader{strings.NewReader(chat)}, "json"},
		{"path", "GET", base + "/api/chat?x=1", nil, "path"},
	}
	for _, c := range cases {
		req, err := http.NewRequest(c.method, c.target, c.body)
		if err != nil {
			t.Fatal(err)
		}
		if c.body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		select {
		case r := <-rows:
			if r.LLMReason != c.want || r.IsLLM != (c.want != "") {
				t.Fatalf("%s: live row isLLM=%v reason=%q, want %q", c.name, r.IsLLM, r.LLMReason, c.want)
			}
			stored := waitDetail(t, b, r.ID)
			if stored.LLMReason != c.want || stored.IsLLM != r.IsLLM {
				t.Fatalf("%s: stored isLLM=%v reason=%q, want %q", c.name, stored.IsLLM, stored.LLMReason, c.want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: no row emitted", c.name)
		}
	}
}

// stalledStore never finishes a write until released: a hung disk.
type stalledStore struct {
	release chan struct{}
	saved   atomic.Int64
}

func (s *stalledStore) InsertBatch(_ context.Context, b []storage.Exchange) error {
	<-s.release
	s.saved.Add(int64(len(b)))
	return nil
}

func (s *stalledStore) GetExchange(context.Context, int64) (storage.Exchange, error) {
	return storage.Exchange{}, storage.ErrNotFound
}

// Forwarding keeps its normal speed while the storage writer is stuck, and
// nothing is lost: once the writer recovers every exchange is saved.
func TestBridgeForwardingNotBlockedByStalledWriter(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	store := &stalledStore{release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	b.useStore(store, "")
	st := b.start(ctx, func([]synth.Exchange) {}, noStorageErrors)

	const n = 300
	// Each request must finish quickly although no row has been written.
	proxyGet(t, st.Addr, "http://"+origin+testorigin.PathContentLength, n, 2*time.Second)
	ss := b.storageStats()
	if store.saved.Load() != 0 || ss.Queued != n || ss.Unsaved != 0 {
		t.Fatalf("while stalled: saved=%d stats %+v", store.saved.Load(), ss)
	}

	close(store.release)
	cancel()
	if err := b.stop(); err != nil {
		t.Fatal(err)
	}
	if got := store.saved.Load(); got != n {
		t.Fatalf("saved %d of %d after recovery", got, n)
	}
}

type brokenStore struct{}

func (brokenStore) InsertBatch(context.Context, []storage.Exchange) error {
	return errors.New("database disk image is malformed")
}

func (brokenStore) GetExchange(context.Context, int64) (storage.Exchange, error) {
	return storage.Exchange{}, storage.ErrNotFound
}

// A storage failure reaches the UI callback and the counters; the proxy keeps
// forwarding.
func TestBridgeSurfacesStorageFailure(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newTestBridge("127.0.0.1:0")
	b.useStore(brokenStore{}, "")
	errs := make(chan string, 16)
	st := b.start(ctx, func([]synth.Exchange) {}, func(msg string) {
		select {
		case errs <- msg:
		default:
		}
	})
	defer func() { cancel(); _ = b.stop() }()

	proxyGet(t, st.Addr, "http://"+origin+testorigin.PathContentLength, 1, 2*time.Second)
	select {
	case msg := <-errs:
		if !strings.Contains(msg, "history incomplete") || !strings.Contains(msg, "malformed") {
			t.Fatalf("error message %q", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("storage failure not surfaced")
	}
	if ss := b.storageStats(); ss.Failed != 1 || ss.LastError == "" || !ss.Available {
		t.Fatalf("stats %+v", ss)
	}
}

// With no project store, exchanges are still forwarded and each one is
// counted as not saved, with the reason.
func TestBridgeWithoutStoreCountsUnsaved(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	b.useStore(nil, "keychain locked")
	st := b.start(ctx, func([]synth.Exchange) {}, noStorageErrors)
	proxyGet(t, st.Addr, "http://"+origin+testorigin.PathContentLength, 2, 2*time.Second)
	cancel()
	_ = b.stop()
	ss := b.storageStats()
	if ss.Available || ss.Error != "keychain locked" || ss.Failed != 2 || !strings.Contains(ss.LastError, "keychain locked") {
		t.Fatalf("stats %+v", ss)
	}
}

// hungStore never finishes an insert until its context is cancelled: a stuck
// disk that still honours cancellation. inside counts inserts in progress.
type hungStore struct{ inside atomic.Int32 }

func (h *hungStore) InsertBatch(ctx context.Context, _ []storage.Exchange) error {
	h.inside.Add(1)
	defer h.inside.Add(-1)
	<-ctx.Done()
	return ctx.Err()
}

func (*hungStore) GetExchange(context.Context, int64) (storage.Exchange, error) {
	return storage.Exchange{}, storage.ErrNotFound
}

// captureLog redirects the standard logger for one test.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// When the drain times out, stop cancels the stuck insert and waits for the
// writer before returning, so the app never closes the store under an
// insert. Rows left in the queue are counted as unsaved and reported.
func TestBridgeStopTimeoutStopsWriterBeforeReturning(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	captureLog(t)
	store := &hungStore{}
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	b.drainTimeout = 100 * time.Millisecond
	b.useStore(store, "")
	st := b.start(ctx, func([]synth.Exchange) {}, noStorageErrors)
	proxyGet(t, st.Addr, "http://"+origin+testorigin.PathContentLength, 3, 2*time.Second)

	cancel()
	err := b.stop()
	if !errors.Is(err, storage.ErrHistoryIncomplete) {
		t.Fatalf("stop = %v, want history incomplete", err)
	}
	if n := store.inside.Load(); n != 0 {
		t.Fatalf("%d inserts still running after stop", n)
	}
	ss := b.storageStats()
	if ss.Enqueued != 3 || ss.Saved != 0 || ss.Failed+ss.Abandoned != 3 || ss.Queued != 0 {
		t.Fatalf("stats %+v", ss)
	}
}

// Errors raised while stop drains the queue (the UI context is already
// gone) are logged, not dropped, and still counted.
func TestBridgeLogsStorageErrorsDuringDrain(t *testing.T) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	logs := captureLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	b := newTestBridge("127.0.0.1:0")
	b.useStore(brokenStore{}, "")
	var uiErrors atomic.Int32
	st := b.start(ctx, func([]synth.Exchange) {}, func(string) { uiErrors.Add(1) })
	cancel() // shutdown has begun: no UI to report to
	proxyGet(t, st.Addr, "http://"+origin+testorigin.PathContentLength, 1, 2*time.Second)
	if err := b.stop(); err != nil {
		t.Fatal(err)
	}
	if got := logs.String(); !strings.Contains(got, "history incomplete") || !strings.Contains(got, "malformed") {
		t.Fatalf("drain error not logged; log = %q", got)
	}
	if uiErrors.Load() != 0 {
		t.Fatal("error sent to the UI after its context was cancelled")
	}
	if ss := b.storageStats(); ss.Failed != 1 {
		t.Fatalf("stats %+v", ss)
	}
}

// If the largest stored id cannot be read, the store is not used (ids
// counted from 0 would collide): the proxy is told the store is
// unavailable, with the reason the status bar shows.
func TestAttachStoreMaxIDFailureMakesStoreUnavailable(t *testing.T) {
	captureLog(t)
	store := openTestStore(t)
	_ = store.Close() // every query now fails, MaxID included
	a := NewApp()
	reason := a.attachStore(context.Background(), store, nil)
	if !strings.Contains(reason, "could not read stored history ids") {
		t.Fatalf("reason = %q", reason)
	}
	if a.store != nil || a.nextID.Load() != 0 {
		t.Fatalf("store kept after MaxID failure: store=%v nextID=%d", a.store, a.nextID.Load())
	}
	if ss := a.proxy.storageStats(); ss.Available || ss.Error != reason {
		t.Fatalf("storage stats %+v", ss)
	}
}

// A usable store starts the id counter past the stored rows.
func TestAttachStoreStartsIDsPastStoredRows(t *testing.T) {
	store := openTestStore(t)
	if err := store.InsertBatch(context.Background(), []storage.Exchange{{ID: 41, Method: "GET", Host: "h", Path: "/"}}); err != nil {
		t.Fatal(err)
	}
	a := NewApp()
	if reason := a.attachStore(context.Background(), store, nil); reason != "" {
		t.Fatalf("reason = %q", reason)
	}
	if a.store != store || a.nextID.Load() != 41 || a.historyMax != 41 || !a.proxy.storageStats().Available {
		t.Fatalf("nextID=%d historyMax=%d", a.nextID.Load(), a.historyMax)
	}
}
