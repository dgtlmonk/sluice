package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// The storage path (SPEC.md, Architecture) has two promises that pull against
// each other:
//
//  1. Forwarding never blocks on storage. A proxy that stalls a browser
//     because a disk is slow is broken.
//  2. History is lossless. A row that was forwarded must be saved, and if it
//     cannot be, the user must be told; it must never vanish silently.
//
// A plain bounded channel cannot keep both: when it is full the producer must
// either block (breaks 1) or drop (breaks 2). Writer resolves it like this:
//
//   - The queue is a slice behind a mutex, bounded by BYTES (MaxQueuedBytes),
//     not by a small row count. Enqueue only appends and returns, so the
//     forwarding goroutine waits at most for a short critical section, never
//     for the disk.
//   - When the writer falls behind (more than BehindRows rows waiting), every
//     enqueue past that mark counts as "behind": a visible early warning, but
//     nothing is lost yet; the rows are only waiting in memory.
//   - Only if the byte budget is exhausted is an exchange refused. That is
//     counted as Unsaved and reported as a "history incomplete" error. This is
//     the one place the queue gives up a row, and it is never silent.
//   - A batch the database refuses (after retries) is split into single-row
//     inserts, so one poison row cannot sink 255 good ones. Only the rows the
//     database still refuses on their own are counted as Failed and reported.
//   - If shutdown gives up waiting (Close timeout), the writer is stopped
//     (the insert in flight is cancelled and awaited) and every row still
//     queued is counted as Abandoned, which is also part of Unsaved.
//
// So the invariant the tests check is:
// Enqueued == Saved + Failed + Queued + Abandoned, with Unsaved counting rows
// never queued plus Abandoned ones, and Failed + Unsaved > 0 always
// accompanied by an error.

// Inserter is what the writer drains into. *Store implements it; tests
// substitute a stalled or failing one.
type Inserter interface {
	InsertBatch(ctx context.Context, batch []Exchange) error
}

// WriterConfig tunes a Writer. Zero values fall back to DefaultWriterConfig.
type WriterConfig struct {
	MaxBatch       int           // rows per transaction
	BehindRows     int           // queue depth that counts as "storage behind"
	MaxQueuedBytes int64         // memory budget for waiting rows; beyond it rows are refused
	Retries        int           // extra attempts for a failed batch
	RetryBase      time.Duration // first retry delay, doubled each attempt
	InsertTimeout  time.Duration // per InsertBatch attempt
}

// DefaultWriterConfig returns the production defaults.
func DefaultWriterConfig() WriterConfig {
	return WriterConfig{
		MaxBatch:       256,
		BehindRows:     4096,
		MaxQueuedBytes: 512 << 20,
		Retries:        3,
		RetryBase:      50 * time.Millisecond,
		InsertTimeout:  30 * time.Second,
	}
}

func (c WriterConfig) withDefaults() WriterConfig {
	d := DefaultWriterConfig()
	if c.MaxBatch <= 0 {
		c.MaxBatch = d.MaxBatch
	}
	if c.BehindRows <= 0 {
		c.BehindRows = d.BehindRows
	}
	if c.MaxQueuedBytes <= 0 {
		c.MaxQueuedBytes = d.MaxQueuedBytes
	}
	if c.Retries < 0 {
		c.Retries = 0
	}
	if c.RetryBase <= 0 {
		c.RetryBase = d.RetryBase
	}
	if c.InsertTimeout <= 0 {
		c.InsertTimeout = d.InsertTimeout
	}
	return c
}

// WriterStats is a snapshot of the writer's counters.
type WriterStats struct {
	Enqueued  uint64 `json:"enqueued"`  // accepted into the queue
	Saved     uint64 `json:"saved"`     // committed to the database
	Failed    uint64 `json:"failed"`    // accepted, then refused by the database
	Unsaved   uint64 `json:"unsaved"`   // refused at the queue (full or closed), plus Abandoned
	Abandoned uint64 `json:"abandoned"` // accepted, then still queued when shutdown gave up
	Behind    uint64 `json:"behind"`    // enqueues that found the queue past BehindRows
	Queued    int    `json:"queued"`    // waiting, including the batch in flight
	LastError string `json:"lastError"` // most recent failure, empty if none
}

// ErrHistoryIncomplete wraps every failure that cost a history row.
var ErrHistoryIncomplete = errors.New("history incomplete")

// Writer is the single storage writer: one goroutine drains the queue in
// batches, one transaction per batch.
type Writer struct {
	ins Inserter
	cfg WriterConfig

	mu       sync.Mutex
	queue    []Exchange
	bytes    int64 // estimated size of queue
	inFlight int   // rows taken by the writer but not yet resolved
	closed   bool
	lastErr  string

	wake chan struct{} // capacity 1: "the queue changed", coalesced
	done chan struct{} // closed when Run returns
	errs chan error    // lossy notifications; counters are the truth

	// stopCtx is cancelled by Close when draining times out: it aborts the
	// insert in flight and makes Run return without taking another batch.
	stopCtx context.Context
	stop    context.CancelFunc

	enqueued, saved, failed, unsaved, behind, abandoned atomic.Uint64
}

// NewWriter returns a writer draining into ins. Call Run to start it.
func NewWriter(ins Inserter, cfg WriterConfig) *Writer {
	stopCtx, stop := context.WithCancel(context.Background())
	return &Writer{
		ins:     ins,
		cfg:     cfg.withDefaults(),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
		errs:    make(chan error, 16),
		stopCtx: stopCtx,
		stop:    stop,
	}
}

// Errors delivers failures for the UI. It is lossy (a slow reader misses
// some) because the forwarding path reports into it; Stats is the lossless
// record.
func (w *Writer) Errors() <-chan error { return w.errs }

// Enqueue hands ex to the writer. It never blocks on the database. It
// reports false when ex was refused (counted as Unsaved, error reported).
func (w *Writer) Enqueue(ex Exchange) bool {
	size := estimateSize(ex)
	w.mu.Lock()
	switch {
	case w.closed:
		w.mu.Unlock()
		w.refuse("storage writer is closed")
		return false
	case w.bytes+size > w.cfg.MaxQueuedBytes && len(w.queue) > 0:
		// len > 0 lets a single oversized row through an empty queue, so
		// one huge exchange is never refused just for being big.
		w.mu.Unlock()
		w.refuse(fmt.Sprintf("storage queue full (%d MiB waiting); the writer is too slow", w.cfg.MaxQueuedBytes>>20))
		return false
	}
	w.queue = append(w.queue, ex)
	w.bytes += size
	isBehind := len(w.queue)+w.inFlight > w.cfg.BehindRows
	w.mu.Unlock()

	w.enqueued.Add(1)
	if isBehind {
		w.behind.Add(1)
	}
	w.signal()
	return true
}

func (w *Writer) refuse(reason string) {
	w.unsaved.Add(1)
	w.report(fmt.Errorf("%w: exchange not saved: %s", ErrHistoryIncomplete, reason))
}

func (w *Writer) signal() {
	select {
	case w.wake <- struct{}{}:
	default: // a wake-up is already pending; the writer will see this row too
	}
}

func (w *Writer) report(err error) {
	w.mu.Lock()
	w.lastErr = err.Error()
	w.mu.Unlock()
	select {
	case w.errs <- err:
	default:
	}
}

// Done is closed once Run has returned: no insert is in flight any more.
func (w *Writer) Done() <-chan struct{} { return w.done }

// Run drains the queue until Close, then writes whatever is still queued and
// returns. Cancelling ctx is NOT a stop signal: it only aborts an insert in
// progress. Shutdown goes through Close so queued rows are not abandoned.
func (w *Writer) Run(ctx context.Context) {
	defer close(w.done)
	// Close's stop also cancels the inserts' context, so a hung insert is
	// interrupted instead of holding shutdown (and the database) forever.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(w.stopCtx, cancel)()
	for {
		if w.stopCtx.Err() != nil {
			return // stopped by Close; it accounts for what is still queued
		}
		batch, closed := w.take()
		if len(batch) == 0 {
			if closed {
				return
			}
			<-w.wake
			continue
		}
		w.write(ctx, batch)
	}
}

// take removes up to MaxBatch rows from the queue.
func (w *Writer) take() ([]Exchange, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := min(len(w.queue), w.cfg.MaxBatch)
	if n == 0 {
		return nil, w.closed
	}
	batch := make([]Exchange, n)
	copy(batch, w.queue)
	// Clear the moved slots so the queue's backing array does not keep the
	// bodies alive, then shift.
	clear(w.queue[:n])
	w.queue = w.queue[n:]
	if len(w.queue) == 0 {
		w.queue = nil // let the backing array go once drained
	}
	for i := range batch {
		w.bytes -= estimateSize(batch[i])
	}
	w.inFlight = n
	return batch, w.closed
}

// write commits one batch, retrying with exponential backoff. A batch that
// still fails is retried row by row, so only the rows the database refuses on
// their own are lost. Nothing is retried forever: an endless retry would
// stall the queue and turn one bad row into a full queue.
func (w *Writer) write(ctx context.Context, batch []Exchange) {
	err := w.insertWithRetry(ctx, batch)
	switch {
	case err == nil:
		w.saved.Add(uint64(len(batch)))
	case len(batch) == 1 || ctx.Err() != nil:
		// Nothing to split, or the writer is stopping: splitting would only
		// fail the same way, one row at a time.
		w.fail(batch, err)
	default:
		w.writeEach(ctx, batch)
	}
	w.mu.Lock()
	w.inFlight = 0
	w.mu.Unlock()
}

// insertWithRetry tries one batch up to 1 + Retries times. The backoff wait
// gives up as soon as ctx is done, so a stopping writer is not held up by a
// sleep.
func (w *Writer) insertWithRetry(ctx context.Context, batch []Exchange) error {
	delay := w.cfg.RetryBase
	var err error
	for attempt := 0; attempt <= w.cfg.Retries; attempt++ {
		if attempt > 0 {
			if !sleepCtx(ctx, delay) {
				return fmt.Errorf("%w (retry abandoned: %w)", err, ctx.Err())
			}
			delay *= 2
		}
		if err = w.insertOnce(ctx, batch); err == nil {
			return nil
		}
	}
	return err
}

func (w *Writer) insertOnce(ctx context.Context, batch []Exchange) error {
	ictx, cancel := context.WithTimeout(ctx, w.cfg.InsertTimeout)
	defer cancel()
	return w.ins.InsertBatch(ictx, batch)
}

// writeEach is the fallback for a batch the database refused as a whole:
// each row gets its own one-row transaction (one attempt; the batch retries
// already covered transient errors), so a single poison row costs only
// itself. It is slower, but it only runs after a failure.
func (w *Writer) writeEach(ctx context.Context, batch []Exchange) {
	for i := range batch {
		if ctx.Err() != nil {
			w.fail(batch[i:], ctx.Err())
			return
		}
		if err := w.insertOnce(ctx, batch[i:i+1]); err != nil {
			w.fail(batch[i:i+1], err)
			continue
		}
		w.saved.Add(1)
	}
}

// fail counts rows as Failed and reports them. The message names the ids
// and the database's reason; it never includes captured headers or bodies.
func (w *Writer) fail(rows []Exchange, err error) {
	w.failed.Add(uint64(len(rows)))
	if len(rows) == 1 {
		w.report(fmt.Errorf("%w: exchange %d not saved: %w", ErrHistoryIncomplete, rows[0].ID, err))
		return
	}
	w.report(fmt.Errorf("%w: %d exchanges not saved: %w", ErrHistoryIncomplete, len(rows), err))
}

// sleepCtx waits for d, or until ctx is done. It reports whether the full
// wait elapsed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Close stops accepting rows and waits up to timeout for the queue to drain.
// If the timeout passes, it stops the writer: the insert in flight is
// cancelled and Close waits for it to return, so when Close returns the
// writer is never inside InsertBatch and the store can be closed safely.
// Rows still queued are then counted as Abandoned (and Unsaved) and returned
// as an error.
func (w *Writer) Close(timeout time.Duration) error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	w.signal()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-w.done:
		return nil
	case <-t.C:
	}
	w.stop()
	// Unbounded on purpose: returning while an insert may still be running
	// would let the caller close the database under it. The insert's
	// context is cancelled, so a well-behaved Inserter returns promptly.
	<-w.done

	w.mu.Lock()
	n := len(w.queue)
	clear(w.queue)
	w.queue, w.bytes = nil, 0
	w.mu.Unlock()
	if n == 0 {
		return nil // the last batch finished during the stop
	}
	w.abandoned.Add(uint64(n))
	w.unsaved.Add(uint64(n))
	err := fmt.Errorf("%w: storage writer did not drain within %s; %d queued exchanges not saved", ErrHistoryIncomplete, timeout, n)
	w.report(err)
	return err
}

// Stats returns the current counters.
func (w *Writer) Stats() WriterStats {
	w.mu.Lock()
	queued, lastErr := len(w.queue)+w.inFlight, w.lastErr
	w.mu.Unlock()
	return WriterStats{
		Enqueued:  w.enqueued.Load(),
		Saved:     w.saved.Load(),
		Failed:    w.failed.Load(),
		Unsaved:   w.unsaved.Load(),
		Abandoned: w.abandoned.Load(),
		Behind:    w.behind.Load(),
		Queued:    queued,
		LastError: lastErr,
	}
}

// estimateSize approximates the memory a queued row holds: its byte slices
// plus a flat allowance for the strings and struct.
func estimateSize(ex Exchange) int64 {
	n := int64(256 + len(ex.Host) + len(ex.Path) + len(ex.Err))
	for _, m := range []*Message{ex.Request, ex.Response} {
		if m != nil {
			n += int64(len(m.RawHeaders) + len(m.RawBody))
		}
	}
	return n
}
