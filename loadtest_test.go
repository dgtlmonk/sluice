package main

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/loadgen"
	"github.com/dgtlmonk/sluice/internal/synth"
	"github.com/dgtlmonk/sluice/internal/testorigin"
)

// envLoad enables the full M2 load gate (10k requests). Unset, only the
// short variant runs so the normal suite stays fast:
//
//	SLUICE_LOAD=1 go test -run TestLoad -count=1 -v .
//
// SLUICE_LOAD_N overrides the request count of the full run.
const envLoad = "SLUICE_LOAD"

// Short always-on variant: the same real path, 500 requests.
func TestLoadShort(t *testing.T) {
	runLoad(t, 500, 16)
}

// M2 acceptance: 10k requests through the real app path with zero storage
// drops (SPEC.md, M2).
func TestLoadFull(t *testing.T) {
	if os.Getenv(envLoad) == "" {
		t.Skip("set " + envLoad + "=1 to run the 10k load gate")
	}
	n := 10_000
	if v, err := strconv.Atoi(os.Getenv("SLUICE_LOAD_N")); err == nil && v > 0 {
		n = v
	}
	runLoad(t, n, 32)
}

// runLoad drives the same bridge the app runs (engine + capture + LLM
// detect + live feed + storage writer) into a temp encrypted store, then
// checks that every response was good and every exchange was stored.
func runLoad(t *testing.T, n, clients int) {
	origin, stopOrigin := testorigin.Start()
	defer stopOrigin()
	store := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newTestBridge("127.0.0.1:0")
	b.useStore(store, "")

	// The emit callback stands in for the Wails event: it only counts, so
	// live drops here mean the feed itself fell behind, not a slow UI.
	var liveRows atomic.Uint64
	var storageErrs atomic.Int64
	st := b.start(ctx, func(batch []synth.Exchange) { liveRows.Add(uint64(len(batch))) },
		func(string) { storageErrs.Add(1) })
	if !st.Listening {
		t.Fatalf("status %+v", st)
	}
	stopped := false
	defer func() {
		if !stopped {
			cancel()
			_ = b.stop()
		}
	}()

	// Sample the storage queue depth while the load runs.
	var peakQueue atomic.Int64
	sampleDone := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-sampleDone:
				return
			case <-tick.C:
				if q := int64(b.storageStats().Queued); q > peakQueue.Load() {
					peakQueue.Store(q)
				}
			}
		}
	}()

	res, err := loadgen.Run(ctx, loadgen.Config{Proxy: st.Addr, Origin: origin, N: n, Concurrency: clients})
	close(sampleDone)
	sampler.Wait()
	if err != nil {
		t.Fatal(err)
	}

	// Let the live feed flush its last batch (one flush interval) so the
	// drop count reflects the load, not the shutdown, which by contract
	// counts the unflushed batch as dropped.
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && b.feed.Stats().Queued > 0; {
		time.Sleep(10 * time.Millisecond)
	}
	liveDuringLoad := b.feed.Stats()

	drainStart := time.Now()
	cancel()
	stopErr := b.stop()
	stopped = true
	drain := time.Since(drainStart)
	if stopErr != nil {
		t.Fatalf("stop: %v", stopErr)
	}

	ss := b.storageStats()
	fs := b.feed.Stats()
	wantN := uint64(n) //nolint:gosec // G115: n is a small positive request count
	t.Logf("LOAD n=%d clients=%d %s", n, clients, res)
	t.Logf("LOAD drain=%s peakQueue=%d live: published=%d emitted=%d dropped=%d (during load %d, emit saw %d) storage: %+v",
		drain.Round(time.Millisecond), peakQueue.Load(), fs.Published, fs.Emitted, fs.Dropped,
		liveDuringLoad.Dropped, liveRows.Load(), ss.WriterStats)
	t.Logf("LOAD by kind %v", res.ByKind)

	if res.OK != n || res.Failed != 0 {
		t.Fatalf("client: ok=%d failed=%d first error: %v", res.OK, res.Failed, res.FirstErr)
	}
	if ss.Enqueued != wantN || ss.Saved != wantN || ss.Failed != 0 || ss.Abandoned != 0 || ss.Unsaved != 0 || ss.Queued != 0 {
		t.Fatalf("storage stats %+v", ss.WriterStats)
	}
	if storageErrs.Load() != 0 {
		t.Fatalf("%d storage errors surfaced", storageErrs.Load())
	}
	// Lossy path: every event is either emitted or counted as dropped.
	if fs.Emitted+fs.Dropped != wantN || liveRows.Load() != fs.Emitted {
		t.Fatalf("live feed stats %+v", fs)
	}
	if b.capture.Pending() != 0 {
		t.Fatalf("%d captures leaked", b.capture.Pending())
	}
	got, err := store.CountExchanges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != int64(n) {
		t.Fatalf("store has %d rows, want %d", got, n)
	}

	// Every stored row: no proxy error, status 200, LLM flag on chat/SSE.
	proxyErrs, llm := 0, 0
	for id := int64(1); id <= int64(n); id++ {
		ex, err := store.GetExchange(context.Background(), id)
		if err != nil {
			t.Fatalf("exchange %d: %v", id, err)
		}
		if ex.Err != "" || ex.Status != 200 {
			proxyErrs++
			if proxyErrs == 1 {
				t.Errorf("exchange %d: status %d err %q", id, ex.Status, ex.Err)
			}
		}
		if ex.IsLLM {
			llm++
		}
	}
	wantLLM := res.ByKind["sse"] + res.ByKind["chat-cl"] + res.ByKind["chat-chunked"]
	t.Logf("LOAD stored rows=%d proxyErrors=%d llmFlagged=%d (want %d)", got, proxyErrs, llm, wantLLM)
	if proxyErrs != 0 {
		t.Fatalf("%d proxy errors", proxyErrs)
	}
	if llm != wantLLM {
		t.Fatalf("llm flagged %d, want %d", llm, wantLLM)
	}
}
