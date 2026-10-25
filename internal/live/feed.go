// Package live implements the lossy live-event path from SPEC.md (Architecture):
// producers publish without ever blocking, overflow is dropped and counted, and a
// single flusher hands batches to the observer (the UI) on a fixed interval.
package live

import (
	"context"
	"sync/atomic"
	"time"
)

// Feed is a bounded, drop-on-overflow event queue drained in batches.
type Feed[T any] struct {
	ch       chan T
	maxBatch int

	published atomic.Uint64
	dropped   atomic.Uint64
	emitted   atomic.Uint64
	buffered  atomic.Int64 // taken off ch by Run but not yet emitted
}

// Stats is a point-in-time snapshot of a Feed's counters.
//
// Dropped counts events rejected by a full queue plus events Run was holding
// when it shut down. Queued counts events waiting in the queue and in Run's
// pending batch. The counters are read one at a time, so under concurrent
// traffic a snapshot can be off by a few in-flight events.
type Stats struct {
	Published uint64 `json:"published"`
	Dropped   uint64 `json:"dropped"`
	Emitted   uint64 `json:"emitted"`
	Queued    int    `json:"queued"`
}

// NewFeed returns a Feed whose queue holds capacity events and whose batches
// never exceed maxBatch events.
func NewFeed[T any](capacity, maxBatch int) *Feed[T] {
	return &Feed[T]{ch: make(chan T, capacity), maxBatch: maxBatch}
}

// Publish enqueues v without blocking. It reports false when the queue is full
// and v was dropped.
func (f *Feed[T]) Publish(v T) bool {
	select {
	case f.ch <- v:
		f.published.Add(1)
		return true
	default:
		f.dropped.Add(1)
		return false
	}
}

// Stats returns the current counters.
func (f *Feed[T]) Stats() Stats {
	return Stats{
		Published: f.published.Load(),
		Dropped:   f.dropped.Load(),
		Emitted:   f.emitted.Load(),
		Queued:    len(f.ch) + int(f.buffered.Load()),
	}
}

// Run drains the queue and calls emit with one batch per interval until ctx is
// done. emit owns the slice it receives. A slow emit stalls draining, the queue
// fills, and Publish starts dropping: back-pressure never reaches producers.
//
// On shutdown the pending batch is counted as dropped rather than flushed:
// ctx is cancelled when the observer is going away (for the app, the Wails
// window is closing), so a final emit could hit a torn-down target or block
// shutdown, and the live path is lossy by contract anyway. Events still in
// the queue stay counted as Queued.
func (f *Feed[T]) Run(ctx context.Context, interval time.Duration, emit func([]T)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	buf := make([]T, 0, f.maxBatch)
	for {
		// A nil channel blocks forever, so a full buffer pauses receiving until the next flush.
		in := f.ch
		if len(buf) >= f.maxBatch {
			in = nil
		}
		select {
		case <-ctx.Done():
			f.dropped.Add(uint64(len(buf)))
			f.buffered.Add(-int64(len(buf)))
			return
		case v := <-in:
			buf = append(buf, v)
			f.buffered.Add(1)
		case <-ticker.C:
			if len(buf) == 0 {
				continue
			}
			emit(buf)
			f.emitted.Add(uint64(len(buf)))
			f.buffered.Add(-int64(len(buf)))
			buf = make([]T, 0, f.maxBatch)
		}
	}
}
