package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/dgtlmonk/sluice/internal/live"
	"github.com/dgtlmonk/sluice/internal/storage"
	"github.com/dgtlmonk/sluice/internal/synth"
)

const (
	eventExchangesBatch = "exchanges:batch"
	eventProxyStatus    = "proxy:status"
	eventStorageError   = "storage:error"
	// maxHistoryRows caps the rows History loads into the grid at startup.
	maxHistoryRows = 10_000
	// envDevSynth=1 enables the M0 synthetic source (Seed/Stream). Off by default.
	envDevSynth       = "SLUICE_DEV_SYNTH"
	flushInterval     = 100 * time.Millisecond
	liveQueueCapacity = 16_384
	liveMaxBatch      = 4_096 // per flush, so the bridge tops out near 40k events/s
	maxSeedChunk      = 10_000
	maxStreamRate     = 100_000
	synthSeed         = 0x51_1CE
	storeReadTimeout  = 10 * time.Second
)

// App is the Wails binding surface. It is glue only: engine-side code lives in
// internal/ and never imports the Wails runtime.
type App struct {
	wailsCtx context.Context // carries the Wails runtime; needed by runtime.EventsEmit
	runCtx   context.Context // cancelled on shutdown; parent of all background work
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	proxy    *proxyBridge
	devSynth bool
	store    *storage.Store // nil if the project could not be opened; set in startup
	// historyMax is the largest stored id at startup. History serves rows up
	// to it; newer rows reach the grid through the live path, so the two
	// never overlap.
	historyMax int64

	gen    synth.Generator
	feed   *live.Feed[synth.Exchange]
	nextID atomic.Int64

	mu     sync.Mutex
	stream *stream // nil when no stream is running
	rate   int
}

// stream is one running synthetic producer.
type stream struct {
	cancel context.CancelFunc
	done   chan struct{} // closed when the producer goroutine has returned
}

// stop cancels the producer and blocks until it has returned, so no event from
// it can be published afterwards. Produce checks ctx before every publish and
// never takes App.mu, so this returns within one event and is safe to call
// while holding App.mu.
func (s *stream) stop() {
	s.cancel()
	<-s.done
}

// AppStats is what the status bar polls.
type AppStats struct {
	Live       live.Stats   `json:"live"` // proxy + synthetic feeds combined
	DevSynth   bool         `json:"devSynth"`
	Streaming  bool         `json:"streaming"`
	RatePerSec int          `json:"ratePerSec"`
	LastID     int64        `json:"lastId"`
	Storage    StorageStats `json:"storage"`
}

// errSynthDisabled is returned by the synthetic-source bindings unless the
// dev toggle is on.
var errSynthDisabled = errors.New("synthetic source is disabled (set " + envDevSynth + "=1)")

func NewApp() *App {
	a := &App{
		devSynth: os.Getenv(envDevSynth) == "1",
		gen:      synth.New(synthSeed),
		feed:     live.NewFeed[synth.Exchange](liveQueueCapacity, liveMaxBatch),
	}
	a.proxy = newProxyBridge(proxyAddrFromEnv(), func() int64 { return a.nextID.Add(1) })
	return a
}

func (a *App) startup(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)

	// Open the project before the proxy starts, so the first exchange
	// already has somewhere to go, and so new row ids start past the stored
	// ones. Failure is not fatal: the proxy still runs and every exchange is
	// counted and reported as not saved.
	store, err := openProject()
	unavailable := a.attachStore(ctx, store, err)

	// Bound methods read runCtx/cancel under mu, so publish them under mu too.
	a.mu.Lock()
	a.wailsCtx = ctx
	a.runCtx, a.cancel = runCtx, cancel
	a.mu.Unlock()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.feed.Run(runCtx, flushInterval, func(batch []synth.Exchange) {
			runtime.EventsEmit(ctx, eventExchangesBatch, batch)
		})
	}()

	// A listen failure is reported, never fatal: the UI shows the reason.
	status := a.proxy.start(runCtx, func(rows []synth.Exchange) {
		runtime.EventsEmit(ctx, eventExchangesBatch, rows)
	}, func(msg string) {
		runtime.EventsEmit(ctx, eventStorageError, msg)
	})
	runtime.EventsEmit(ctx, eventProxyStatus, status)
	if unavailable != "" {
		runtime.EventsEmit(ctx, eventStorageError, "history is not being saved: "+unavailable)
	}
}

// attachStore hands the opened project store (or the reason there is none)
// to the proxy and starts the id counter past the stored rows. It returns
// why history is unavailable, or "" when the store is usable.
//
// If the largest stored id cannot be read, the store is treated as
// unavailable rather than counted from 0: new ids would collide with stored
// rows, so the proxy keeps forwarding while every exchange is counted and
// reported as not saved, with this reason.
func (a *App) attachStore(ctx context.Context, store *storage.Store, openErr error) string {
	reason := ""
	if openErr != nil {
		reason = openErr.Error() // errors here never carry the key
	} else if maxID, err := store.MaxID(ctx); err != nil {
		reason = "could not read stored history ids: " + err.Error()
		if cerr := store.Close(); cerr != nil {
			log.Printf("storage: close: %v", cerr)
		}
	} else {
		a.store = store
		a.historyMax = maxID
		a.nextID.Store(maxID)
		a.proxy.useStore(store, "")
		return ""
	}
	log.Printf("storage: %s", reason)
	a.proxy.useStore(nil, reason)
	return reason
}

// shutdown stops the producer and flusher and waits for both to exit.
func (a *App) shutdown(_ context.Context) {
	// Cancel under mu so a concurrent StartStream sees runCtx done and refuses
	// to start a new producer.
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.stopStreamLocked()
	a.mu.Unlock()
	if err := a.proxy.stop(); err != nil {
		log.Printf("storage: %v", err)
	}
	a.wg.Wait()
	// proxy.stop has waited for the storage writer to exit (cancelling a
	// stuck insert if the drain timed out), so nothing is inside the store.
	if a.store != nil {
		if err := a.store.Close(); err != nil {
			log.Printf("storage: close: %v", err)
		}
	}
}

// History returns the newest stored exchanges (metadata only, oldest first)
// so the grid shows past sessions on startup.
func (a *App) History(limit int) ([]synth.Exchange, error) {
	if a.store == nil {
		return nil, nil
	}
	if limit < 1 || limit > maxHistoryRows {
		return nil, fmt.Errorf("history limit must be 1..%d, got %d", maxHistoryRows, limit)
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeReadTimeout)
	defer cancel()
	stored, err := a.store.RecentExchanges(ctx, limit, a.historyMax)
	if err != nil {
		return nil, err
	}
	rows := make([]synth.Exchange, len(stored))
	for i, ex := range stored {
		rows[i] = rowFromStored(ex)
	}
	return rows, nil
}

// ProxyStatus reports whether the proxy is listening (and where) or why not.
func (a *App) ProxyStatus() ProxyStatus {
	return a.proxy.Status()
}

// SeedRows returns n freshly generated exchanges. The frontend seeds large
// tables in chunks so no single bridge message gets huge.
func (a *App) SeedRows(n int) ([]synth.Exchange, error) {
	if !a.devSynth {
		return nil, errSynthDisabled
	}
	if n < 1 || n > maxSeedChunk {
		return nil, fmt.Errorf("seed chunk must be 1..%d rows, got %d", maxSeedChunk, n)
	}
	now := time.Now()
	rows := make([]synth.Exchange, n)
	for i := range rows {
		rows[i] = a.gen.Exchange(a.nextID.Add(1), now)
	}
	return rows, nil
}

// StartStream starts (or restarts at a new rate) the synthetic producer.
// Exchanges arrive on the "exchanges:batch" event roughly every 100 ms.
func (a *App) StartStream(ratePerSec int) error {
	if !a.devSynth {
		return errSynthDisabled
	}
	if ratePerSec < 1 || ratePerSec > maxStreamRate {
		return fmt.Errorf("rate must be 1..%d per second, got %d", maxStreamRate, ratePerSec)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.runCtx == nil || a.runCtx.Err() != nil {
		return fmt.Errorf("app is not running")
	}
	// Wait for the old producer to exit before starting the new one; otherwise
	// both publish for a moment (a burst, with interleaved IDs).
	a.stopStreamLocked()

	ctx, cancel := context.WithCancel(a.runCtx)
	s := &stream{cancel: cancel, done: make(chan struct{})}
	a.stream = s
	a.rate = ratePerSec

	go func() {
		defer close(s.done)
		a.gen.Produce(ctx, ratePerSec, func() int64 { return a.nextID.Add(1) }, a.feed.Publish)
	}()
	return nil
}

// StopStream stops the producer and waits for it to exit. Events already
// queued are still flushed.
func (a *App) StopStream() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopStreamLocked()
}

// stopStreamLocked stops the running producer, if any. Caller holds a.mu.
func (a *App) stopStreamLocked() {
	if a.stream != nil {
		a.stream.stop()
		a.stream = nil
	}
	a.rate = 0
}

// Stats reports live-path counters for the status bar.
func (a *App) Stats() AppStats {
	a.mu.Lock()
	streaming, rate := a.stream != nil, a.rate
	a.mu.Unlock()
	return AppStats{
		Live:       sumStats(a.feed.Stats(), a.proxy.feed.Stats()),
		DevSynth:   a.devSynth,
		Streaming:  streaming,
		RatePerSec: rate,
		LastID:     a.nextID.Load(),
		Storage:    a.proxy.storageStats(),
	}
}

// ExchangeDetail returns the raw request/response text for one exchange.
// Proxied rows are read from the store; synthetic rows are regenerated from
// their id.
func (a *App) ExchangeDetail(id int64) (synth.Detail, error) {
	ctx, cancel := context.WithTimeout(context.Background(), storeReadTimeout)
	defer cancel()
	d, found, err := a.proxy.detail(ctx, id)
	switch {
	case err != nil:
		return synth.Detail{}, err
	case found:
		return d, nil
	case a.devSynth:
		return a.gen.Detail(id), nil
	}
	return synth.Detail{ID: id, Request: "(not in the store yet: the storage writer has not committed this exchange, or it was not saved; see the status bar)"}, nil
}

func sumStats(x, y live.Stats) live.Stats {
	return live.Stats{
		Published: x.Published + y.Published,
		Dropped:   x.Dropped + y.Dropped,
		Emitted:   x.Emitted + y.Emitted,
		Queued:    x.Queued + y.Queued,
	}
}
