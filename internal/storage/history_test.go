package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3/driver"
)

func fullExchange(id int64) Exchange {
	return Exchange{
		ID:        id,
		StartedAt: time.UnixMilli(1_761_300_000_000 + id),
		Duration:  1234 * time.Millisecond,
		Scheme:    "http",
		Host:      "origin.test",
		Port:      8080,
		Method:    "POST",
		Path:      fmt.Sprintf("/v1/items/%d?q=1", id),
		Status:    502,
		ReqSize:   11,
		RespSize:  7,
		Err:       "bad gateway: connection refused",
		Tool:      "proxy",
		IsLLM:     true,
		LLMReason: "path,sse",
		Request: &Message{
			RawHeaders: []byte("POST http://origin.test:8080/v1/items HTTP/1.1\r\nCookie: s=1\r\nTransfer-Encoding: chunked\r\n\r\n"),
			RawBody:    []byte("b\r\nhello world\r\n0\r\n\r\n\x00\xff"), // binary-safe
		},
		Response: &Message{
			RawHeaders:    []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 7\r\n\r\n"),
			RawBody:       []byte("refused"),
			BodyTruncated: true,
		},
	}
}

func TestRoundTripAllFields(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "p.sluice"), newKey(t))
	ctx := context.Background()
	want := fullExchange(42)
	if err := s.InsertBatch(ctx, []Exchange{want}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetExchange(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v\n req %+v / %+v\nresp %+v / %+v",
			got, want, got.Request, want.Request, got.Response, want.Response)
	}
}

func TestRestartReloadsHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	key := newKey(t)
	ctx := context.Background()

	s := openStore(t, path, key)
	var batch []Exchange
	for i := int64(1); i <= 50; i++ {
		batch = append(batch, fullExchange(i))
	}
	if err := s.InsertBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openStore(t, path, key)
	recent, err := s.RecentExchanges(ctx, 10, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 10 || recent[0].ID != 41 || recent[9].ID != 50 {
		t.Fatalf("recent ids: %v", ids(recent))
	}
	for _, ex := range recent {
		if ex.Request != nil || ex.Response != nil {
			t.Fatal("RecentExchanges must not load messages")
		}
		want := fullExchange(ex.ID)
		want.Request, want.Response = nil, nil
		if !reflect.DeepEqual(ex, want) {
			t.Fatalf("metadata mismatch:\n got %+v\nwant %+v", ex, want)
		}
	}
	if older, _ := s.RecentExchanges(ctx, 3, 20); len(older) != 3 || older[2].ID != 20 {
		t.Fatalf("bounded window ids: %v", ids(older))
	}
	if maxID, err := s.MaxID(ctx); err != nil || maxID != 50 {
		t.Fatalf("MaxID = %d, %v", maxID, err)
	}
	full, err := s.GetExchange(ctx, 50)
	if err != nil || !bytes.Equal(full.Request.RawBody, fullExchange(50).Request.RawBody) {
		t.Fatalf("GetExchange after reopen: %+v, %v", full, err)
	}
}

func ids(xs []Exchange) []int64 {
	out := make([]int64, len(xs))
	for i, x := range xs {
		out[i] = x.ID
	}
	return out
}

func TestInsertBatchIsAtomic(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "p.sluice"), newKey(t))
	ctx := context.Background()
	// The second row reuses id 1, so the batch must fail as a whole.
	err := s.InsertBatch(ctx, []Exchange{fullExchange(1), fullExchange(1)})
	if err == nil {
		t.Fatal("duplicate id accepted")
	}
	if n, _ := s.CountExchanges(ctx); n != 0 {
		t.Fatalf("partial batch committed: %d rows", n)
	}
}

func TestMigrationsMatchVersion(t *testing.T) {
	if len(migrations) != schemaVersion {
		t.Fatalf("%d migrations for schema version %d", len(migrations), schemaVersion)
	}
}

// An M0 (version 1) project opens, gains the error column, and keeps its rows.
func TestMigrateFromV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	key := newKey(t)
	if err := createPrivateFile(path); err != nil {
		t.Fatal(err)
	}
	db, err := driver.Open(buildDSN(path), connInit(hex.EncodeToString(key)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, q := range []string{
		"PRAGMA journal_mode = WAL",
		migrations[0],
		"PRAGMA user_version = 1",
		`INSERT INTO exchanges (id, started_at, scheme, host, port, method, path, tool)
		 VALUES (7, 1000, 'http', 'old.test', 80, 'GET', '/', 'proxy')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s := openStore(t, path, key)
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil || v != schemaVersion {
		t.Fatalf("user_version = %d, %v", v, err)
	}
	got, err := s.GetExchange(ctx, 7)
	if err != nil || got.Host != "old.test" || got.Err != "" {
		t.Fatalf("old row: %+v, %v", got, err)
	}
	ex := fullExchange(8)
	if err := s.InsertBatch(ctx, []Exchange{ex}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetExchange(ctx, 8); got.Err != ex.Err {
		t.Fatalf("error column after migration: %q", got.Err)
	}
}

// A version 2 project (M2 before LLM flagging) gains llm_reason; old rows
// read it as empty and keep their is_llm value.
func TestMigrateFromV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	key := newKey(t)
	if err := createPrivateFile(path); err != nil {
		t.Fatal(err)
	}
	db, err := driver.Open(buildDSN(path), connInit(hex.EncodeToString(key)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, q := range []string{
		"PRAGMA journal_mode = WAL",
		migrations[0],
		migrations[1],
		"PRAGMA user_version = 2",
		`INSERT INTO exchanges (id, started_at, scheme, host, port, method, path, tool, is_llm)
		 VALUES (7, 1000, 'http', 'old.test', 80, 'GET', '/', 'proxy', 1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s := openStore(t, path, key)
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil || v != schemaVersion {
		t.Fatalf("user_version = %d, %v", v, err)
	}
	got, err := s.GetExchange(ctx, 7)
	if err != nil || !got.IsLLM || got.LLMReason != "" {
		t.Fatalf("old row: %+v, %v", got, err)
	}
	ex := fullExchange(8)
	if err := s.InsertBatch(ctx, []Exchange{ex}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetExchange(ctx, 8); got.LLMReason != ex.LLMReason {
		t.Fatalf("llm_reason after migration: %q", got.LLMReason)
	}
}

func TestCaptureCapsBody(t *testing.T) {
	c := NewCapture(8)
	c.Head(1, false, []byte("GET / HTTP/1.1\r\n\r\n"))
	c.Body(1, false, []byte("12345"))
	c.Body(1, false, []byte("67890"))
	c.Body(1, false, []byte("x"))
	c.Body(1, true, []byte("ok"))
	if c.Pending() != 1 {
		t.Fatalf("pending = %d", c.Pending())
	}
	req, resp := c.Finish(1)
	if string(req.RawBody) != "12345678" || !req.BodyTruncated {
		t.Fatalf("req %+v", req)
	}
	if resp.RawHeaders != nil || string(resp.RawBody) != "ok" || resp.BodyTruncated {
		t.Fatalf("resp %+v", resp)
	}
	if req2, resp2 := c.Finish(1); req2 != nil || resp2 != nil || c.Pending() != 0 {
		t.Fatal("Finish must remove the draft")
	}
}

func TestCaptureCopiesInput(t *testing.T) {
	c := NewCapture(0)
	buf := []byte("abc")
	c.Head(1, false, buf)
	c.Body(1, false, buf)
	copy(buf, "zzz")
	req, _ := c.Finish(1)
	if string(req.RawHeaders) != "abc" || string(req.RawBody) != "abc" {
		t.Fatalf("capture aliases caller memory: %+v", req)
	}
}

// --- Writer ---

func runWriter(t *testing.T, ins Inserter, cfg WriterConfig) *Writer {
	t.Helper()
	w := NewWriter(ins, cfg)
	go w.Run(context.Background())
	t.Cleanup(func() { _ = w.Close(5 * time.Second) })
	return w
}

func checkInvariant(t *testing.T, st WriterStats) {
	t.Helper()
	if st.Enqueued != st.Saved+st.Failed+st.Abandoned+uint64(st.Queued) { //nolint:gosec // G115: Queued is a len(), never negative
		t.Fatalf("lost rows: %+v", st)
	}
}

// A burst far larger than one batch lands completely, in multi-row batches.
func TestWriterBurstZeroDrops(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "p.sluice"), newKey(t))
	w := runWriter(t, s, WriterConfig{})
	const n = 10_000
	var wg sync.WaitGroup
	for g := range 8 { // several producers, as with many client connections
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := g; i < n; i += 8 {
				ex := fullExchange(int64(i + 1))
				if !w.Enqueue(ex) {
					t.Errorf("enqueue %d refused", i)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := w.Close(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	st := w.Stats()
	checkInvariant(t, st)
	if st.Saved != n || st.Failed != 0 || st.Unsaved != 0 || st.LastError != "" {
		t.Fatalf("stats %+v, want %d saved and no errors", st, n)
	}
	if got, _ := s.CountExchanges(context.Background()); got != n {
		t.Fatalf("rows in store = %d, want %d", got, n)
	}
}

type failingInserter struct{ calls int }

func (f *failingInserter) InsertBatch(context.Context, []Exchange) error {
	f.calls++
	return errors.New("disk I/O error")
}

// A database failure is retried, then counted and reported, never silent.
func TestWriterSurfacesStorageFailure(t *testing.T) {
	ins := &failingInserter{}
	w := runWriter(t, ins, WriterConfig{Retries: 2, RetryBase: time.Millisecond})
	w.Enqueue(fullExchange(1))

	select {
	case err := <-w.Errors():
		if !errors.Is(err, ErrHistoryIncomplete) || !strings.Contains(err.Error(), "disk I/O error") {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("storage failure was not reported")
	}
	if err := w.Close(time.Second); err != nil {
		t.Fatal(err)
	}
	st := w.Stats()
	checkInvariant(t, st)
	if st.Failed != 1 || st.Saved != 0 || st.LastError == "" {
		t.Fatalf("stats %+v", st)
	}
	if ins.calls != 3 {
		t.Fatalf("InsertBatch called %d times, want 1 + 2 retries", ins.calls)
	}
}

// stalledInserter blocks every insert until released, like a hung disk.
type stalledInserter struct {
	release chan struct{}
	mu      sync.Mutex
	rows    int
}

func (s *stalledInserter) InsertBatch(_ context.Context, b []Exchange) error {
	<-s.release
	s.mu.Lock()
	s.rows += len(b)
	s.mu.Unlock()
	return nil
}

// With the writer stuck, Enqueue still returns at once and keeps every row;
// "behind" is counted; once the writer recovers everything is saved.
func TestWriterStalledDoesNotBlockOrLose(t *testing.T) {
	ins := &stalledInserter{release: make(chan struct{})}
	w := runWriter(t, ins, WriterConfig{BehindRows: 100})
	const n = 5_000
	start := time.Now()
	for i := range n {
		if !w.Enqueue(fullExchange(int64(i + 1))) {
			t.Fatalf("enqueue %d refused while under the byte budget", i)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("enqueue blocked: %d rows took %s", n, d)
	}
	st := w.Stats()
	if st.Behind == 0 || st.Unsaved != 0 || st.Queued != n {
		t.Fatalf("stalled stats %+v", st)
	}
	checkInvariant(t, st)

	close(ins.release)
	if err := w.Close(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	st = w.Stats()
	checkInvariant(t, st)
	if st.Saved != n || ins.rows != n {
		t.Fatalf("after recovery %+v, inserted %d", st, ins.rows)
	}
}

// Past the byte budget a row is refused, counted and reported: the one way
// the queue gives a row up, and never quietly.
func TestWriterFullQueueRefusesLoudly(t *testing.T) {
	ins := &stalledInserter{release: make(chan struct{})}
	defer close(ins.release)
	one := estimateSize(fullExchange(1))
	w := runWriter(t, ins, WriterConfig{MaxQueuedBytes: 3 * one, MaxBatch: 1})

	accepted := 0
	for i := range 10 {
		if w.Enqueue(fullExchange(int64(i + 1))) {
			accepted++
		}
	}
	st := w.Stats()
	if st.Unsaved == 0 || int(st.Unsaved)+accepted != 10 { //nolint:gosec // G115: at most 10
		t.Fatalf("stats %+v, accepted %d", st, accepted)
	}
	checkInvariant(t, st)
	select {
	case err := <-w.Errors():
		if !errors.Is(err, ErrHistoryIncomplete) {
			t.Fatalf("error = %v", err)
		}
	default:
		t.Fatal("refusal was not reported")
	}
}

func TestWriterRefusesAfterClose(t *testing.T) {
	w := runWriter(t, &failingInserter{}, WriterConfig{})
	if err := w.Close(time.Second); err != nil {
		t.Fatal(err)
	}
	if w.Enqueue(fullExchange(1)) || w.Stats().Unsaved != 1 {
		t.Fatalf("enqueue after close: %+v", w.Stats())
	}
}

// One poison row (here: an id already in the store) makes the batch
// transaction fail every retry. The writer then saves row by row: the good
// rows land and only the poison row is counted as failed, with its id.
func TestWriterPoisonRowCostsOnlyItself(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, filepath.Join(t.TempDir(), "p.sluice"), newKey(t))
	if err := s.InsertBatch(ctx, []Exchange{fullExchange(7)}); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(s, WriterConfig{Retries: 1, RetryBase: time.Millisecond})
	for i := range 10 { // queued before Run, so they form one batch
		w.Enqueue(fullExchange(int64(i + 1)))
	}
	go w.Run(ctx)
	if err := w.Close(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	st := w.Stats()
	checkInvariant(t, st)
	if st.Saved != 9 || st.Failed != 1 || !strings.Contains(st.LastError, "exchange 7 not saved") {
		t.Fatalf("stats %+v", st)
	}
	if got, _ := s.CountExchanges(ctx); got != 10 { // 9 new + the original 7
		t.Fatalf("rows in store = %d, want 10", got)
	}
}

// hungInserter blocks until its context is cancelled, like a stuck disk
// that still honours cancellation. inside counts calls in progress.
type hungInserter struct{ inside atomic.Int32 }

func (h *hungInserter) InsertBatch(ctx context.Context, _ []Exchange) error {
	h.inside.Add(1)
	defer h.inside.Add(-1)
	<-ctx.Done()
	return ctx.Err()
}

// When the drain times out, Close cancels the insert in flight and waits
// for it, so on return nothing is inside InsertBatch (the store may be
// closed). The rows still queued are counted as abandoned and unsaved.
func TestWriterCloseTimeoutStopsWriterFirst(t *testing.T) {
	ins := &hungInserter{}
	w := NewWriter(ins, WriterConfig{MaxBatch: 1, Retries: 0})
	go w.Run(context.Background())
	for i := range 3 {
		w.Enqueue(fullExchange(int64(i + 1)))
	}
	err := w.Close(50 * time.Millisecond)
	if !errors.Is(err, ErrHistoryIncomplete) || !strings.Contains(err.Error(), "2 queued exchanges not saved") {
		t.Fatalf("Close = %v", err)
	}
	if n := ins.inside.Load(); n != 0 {
		t.Fatalf("%d inserts still running after Close", n)
	}
	select {
	case <-w.Done():
	default:
		t.Fatal("writer still running after Close")
	}
	st := w.Stats()
	checkInvariant(t, st)
	if st.Failed != 1 || st.Abandoned != 2 || st.Unsaved != 2 || st.Queued != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// The retry backoff is cut short when the writer is stopped: an hour-long
// backoff does not hold shutdown.
func TestWriterRetryWaitHonoursStop(t *testing.T) {
	w := NewWriter(&failingInserter{}, WriterConfig{Retries: 1, RetryBase: time.Hour})
	go w.Run(context.Background())
	w.Enqueue(fullExchange(1))
	start := time.Now()
	if err := w.Close(50 * time.Millisecond); err != nil {
		t.Fatalf("Close = %v (nothing should be left queued)", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close took %s: retry sleep ignored the stop", d)
	}
	st := w.Stats()
	checkInvariant(t, st)
	if st.Failed != 1 || !strings.Contains(st.LastError, "retry abandoned") {
		t.Fatalf("stats %+v", st)
	}
}

var _ Inserter = (*Store)(nil)
