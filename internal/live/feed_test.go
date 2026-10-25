package live

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestPublishDropsWhenFull(t *testing.T) {
	f := NewFeed[int](2, 10)
	for i := range 5 {
		f.Publish(i)
	}
	s := f.Stats()
	if s.Published != 2 || s.Dropped != 3 || s.Queued != 2 {
		t.Fatalf("got %+v, want published=2 dropped=3 queued=2", s)
	}
}

func TestRunEmitsBatchesInOrder(t *testing.T) {
	f := NewFeed[int](100, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu  sync.Mutex
		got []int
	)
	done := make(chan struct{})
	go func() {
		f.Run(ctx, 5*time.Millisecond, func(batch []int) {
			mu.Lock()
			got = append(got, batch...)
			mu.Unlock()
		})
		close(done)
	}()

	for i := range 50 {
		f.Publish(i)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 50 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 50 events emitted", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("event %d out of order: got %d", i, v)
		}
	}
	if s := f.Stats(); s.Emitted != 50 {
		t.Fatalf("emitted = %d, want 50", s.Emitted)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// Events Run has taken off the queue but not yet emitted count as Queued, and
// on shutdown they count as Dropped instead of vanishing.
func TestRunCountsPendingBatchOnShutdown(t *testing.T) {
	f := NewFeed[int](10, 10)
	for i := range 3 {
		f.Publish(i)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		// The interval is long enough that no flush happens during the test.
		f.Run(ctx, time.Hour, func([]int) { t.Error("unexpected emit") })
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for len(f.ch) > 0 || f.buffered.Load() != 3 {
		if time.Now().After(deadline) {
			t.Fatalf("Run did not drain the queue: %+v", f.Stats())
		}
		time.Sleep(time.Millisecond)
	}
	if s := f.Stats(); s.Queued != 3 {
		t.Fatalf("queued = %d, want 3 (pending batch)", s.Queued)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
	s := f.Stats()
	if s.Published != 3 || s.Dropped != 3 || s.Emitted != 0 || s.Queued != 0 {
		t.Fatalf("got %+v, want published=3 dropped=3 emitted=0 queued=0", s)
	}
}
