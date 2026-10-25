package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/dgtlmonk/sluice/internal/live"
	"github.com/dgtlmonk/sluice/internal/synth"
)

const (
	eventExchangesBatch = "exchanges:batch"
	flushInterval       = 100 * time.Millisecond
	liveQueueCapacity   = 16_384
	liveMaxBatch        = 4_096 // per flush, so the bridge tops out near 40k events/s
	maxSeedChunk        = 10_000
	maxStreamRate       = 100_000
	synthSeed           = 0x51_1CE
)

// App is the Wails binding surface. It is glue only: engine-side code lives in
// internal/ and never imports the Wails runtime.
type App struct {
	wailsCtx context.Context // carries the Wails runtime; needed by runtime.EventsEmit
	runCtx   context.Context // cancelled on shutdown; parent of all background work
	cancel   context.CancelFunc
	wg       sync.WaitGroup

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
	Live       live.Stats `json:"live"`
	Streaming  bool       `json:"streaming"`
	RatePerSec int        `json:"ratePerSec"`
	LastID     int64      `json:"lastId"`
}

func NewApp() *App {
	return &App{
		gen:  synth.New(synthSeed),
		feed: live.NewFeed[synth.Exchange](liveQueueCapacity, liveMaxBatch),
	}
}

func (a *App) startup(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)

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
	a.wg.Wait()
}

// SeedRows returns n freshly generated exchanges. The frontend seeds large
// tables in chunks so no single bridge message gets huge.
func (a *App) SeedRows(n int) ([]synth.Exchange, error) {
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
		Live:       a.feed.Stats(),
		Streaming:  streaming,
		RatePerSec: rate,
		LastID:     a.nextID.Load(),
	}
}

// ExchangeDetail returns the raw request/response text for one exchange.
func (a *App) ExchangeDetail(id int64) synth.Detail {
	return a.gen.Detail(id)
}
