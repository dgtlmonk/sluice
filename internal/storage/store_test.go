package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// marker is a plaintext value that must never appear in the raw files.
var marker = []byte("SLUICE-PLAINTEXT-MARKER-7f3a9c")

func newKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func openStore(t *testing.T, path string, key []byte) *Store {
	t.Helper()
	s, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// sql.DB.Close is idempotent, so tests may also Close explicitly.
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func sampleExchange() Exchange {
	return Exchange{
		StartedAt: time.UnixMilli(1_761_300_000_123),
		Scheme:    "https",
		Host:      "example.test",
		Port:      443,
		Method:    "POST",
		Path:      "/login",
		Tool:      "proxy",
		Request: &Message{
			RawHeaders: []byte("POST /login HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer secret\r\n\r\n"),
			RawBody:    append([]byte("password="), marker...),
		},
		Response: &Message{
			RawHeaders: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		},
	}
}

func insertSample(t *testing.T, s *Store) int64 {
	t.Helper()
	id, err := s.InsertExchange(context.Background(), sampleExchange())
	if err != nil {
		t.Fatalf("InsertExchange: %v", err)
	}
	return id
}

func assertSample(t *testing.T, got Exchange) {
	t.Helper()
	want := sampleExchange()
	if !got.StartedAt.Equal(want.StartedAt) || got.Scheme != want.Scheme || got.Host != want.Host ||
		got.Port != want.Port || got.Method != want.Method || got.Path != want.Path || got.Tool != want.Tool {
		t.Fatalf("exchange mismatch:\n got %+v\nwant %+v", got, want)
	}
	if got.Request == nil || !bytes.Equal(got.Request.RawHeaders, want.Request.RawHeaders) ||
		!bytes.Equal(got.Request.RawBody, want.Request.RawBody) {
		t.Fatalf("request mismatch: %+v", got.Request)
	}
	if got.Response == nil || !bytes.Equal(got.Response.RawHeaders, want.Response.RawHeaders) ||
		len(got.Response.RawBody) != 0 {
		t.Fatalf("response mismatch: %+v", got.Response)
	}
}

func TestOpenRejectsBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		_, err := Open(filepath.Join(t.TempDir(), "p.sluice"), make([]byte, n))
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("key len %d: got %v, want ErrInvalidKey", n, err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "p.sluice"), newKey(t))

	id := insertSample(t, s)
	got, err := s.GetExchange(context.Background(), id)
	if err != nil {
		t.Fatalf("GetExchange: %v", err)
	}
	assertSample(t, got)

	if _, err := s.GetExchange(context.Background(), id+1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id: got %v, want ErrNotFound", err)
	}
}

// The default project lives under "Application Support", so paths with
// spaces (and other URI-special characters) must survive the SQLite URI.
func TestOpenPathWithSpecialCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Application Support", "a+b %20 c", "p.sluice")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, path, newKey(t))
	id := insertSample(t, s)
	got, err := s.GetExchange(context.Background(), id)
	if err != nil {
		t.Fatalf("GetExchange: %v", err)
	}
	assertSample(t, got)
}

func TestReopenWithSameKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	key := newKey(t)

	s := openStore(t, path, key)
	id := insertSample(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openStore(t, path, key) // migration must be a no-op on reopen
	got, err := s.GetExchange(context.Background(), id)
	if err != nil {
		t.Fatalf("GetExchange after reopen: %v", err)
	}
	assertSample(t, got)
}

func TestWrongKeyFailsCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	key := newKey(t)

	s := openStore(t, path, key)
	id := insertSample(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path, newKey(t)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: got %v, want ErrWrongKey", err)
	}

	// The failed attempt must not have damaged the file.
	s = openStore(t, path, key)
	got, err := s.GetExchange(context.Background(), id)
	if err != nil {
		t.Fatalf("GetExchange after wrong-key attempt: %v", err)
	}
	assertSample(t, got)
}

// TestFilesAreEncrypted checks the raw bytes on disk: the main file, and the
// WAL while it still holds the uncheckpointed write.
func TestFilesAreEncrypted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	s := openStore(t, path, newKey(t))
	insertSample(t, s)

	walInfo, err := os.Stat(path + "-wal")
	if err != nil {
		t.Fatalf("stat WAL: %v", err)
	}
	if walInfo.Size() == 0 {
		t.Fatal("WAL is empty after a write; expected uncheckpointed frames")
	}
	assertNoPlaintext(t, path)
	assertNoPlaintext(t, path+"-wal")

	if err := s.Close(); err != nil { // checkpoints WAL into the main file
		t.Fatal(err)
	}
	assertNoPlaintext(t, path)
}

func assertNoPlaintext(t *testing.T, file string) {
	t.Helper()
	raw, err := os.ReadFile(file) //nolint:gosec // G304: test reads its own temp files
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatalf("%s is empty", filepath.Base(file))
	}
	if bytes.Contains(raw, marker) {
		t.Errorf("%s contains the plaintext marker", filepath.Base(file))
	}
	if bytes.Contains(raw, []byte("SQLite format 3")) {
		t.Errorf("%s contains the SQLite header", filepath.Base(file))
	}
	if bytes.Contains(raw, []byte("CREATE TABLE")) {
		t.Errorf("%s contains plaintext schema", filepath.Base(file))
	}
}

// TestWALActive checks WAL mode on several distinct pooled connections, which
// also proves the per-connection key hook runs on each of them: an unkeyed
// connection would fail to read the schema.
func TestWALActive(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "p.sluice"), newKey(t))
	insertSample(t, s)

	ctx := context.Background()
	const n = 3
	for i := range n {
		conn, err := s.db.Conn(ctx) // held open, so each iteration gets a new connection
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })

		var mode, tempStore string
		var count int
		if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
			t.Fatalf("conn %d journal_mode: %v", i, err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA temp_store").Scan(&tempStore); err != nil {
			t.Fatalf("conn %d temp_store: %v", i, err)
		}
		if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM exchanges").Scan(&count); err != nil {
			t.Fatalf("conn %d read: %v", i, err)
		}
		if mode != "wal" {
			t.Errorf("conn %d journal_mode = %q, want wal", i, mode)
		}
		if tempStore != "2" { // 2 = MEMORY
			t.Errorf("conn %d temp_store = %q, want 2 (memory)", i, tempStore)
		}
		if count != 1 {
			t.Errorf("conn %d count = %d, want 1", i, count)
		}
	}
	if got := s.db.Stats().OpenConnections; got < n {
		t.Fatalf("only %d pooled connections, want >= %d", got, n)
	}
}

func TestFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	s := openStore(t, path, newKey(t))
	insertSample(t, s)

	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatalf("stat %s: %v", filepath.Base(f), err)
		}
		if perm := info.Mode().Perm(); perm != fileMode {
			t.Errorf("%s mode = %o, want %o", filepath.Base(f), perm, fileMode)
		}
	}
}

func TestOpenTightensExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	// Deliberately too open: Open must tighten it.
	if err := os.WriteFile(path, nil, 0o644); err != nil { //nolint:gosec // G306: see above
		t.Fatal(err)
	}
	openStore(t, path, newKey(t))

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != fileMode {
		t.Fatalf("mode = %o, want %o", perm, fileMode)
	}
}

func TestOpenRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil { //nolint:gosec // G306: mode is what we check stays untouched
		t.Fatal(err)
	}
	link := filepath.Join(dir, "p.sluice")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	s, err := Open(link, newKey(t))
	if err == nil {
		_ = s.Close()
		t.Fatal("Open followed a symlinked project path")
	}
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("err = %v, want ErrSymlink", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("link target mode changed to %o", perm)
	}
}

func TestOpenRejectsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "missing")
	link := filepath.Join(dir, "p.sluice")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(link, newKey(t)); !errors.Is(err, ErrSymlink) {
		t.Fatalf("err = %v, want ErrSymlink", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("link target was created (lstat err = %v)", err)
	}
}

// Separate *sql.DB pools lock the file through the OS like separate processes
// do, so concurrent Opens of one new project exercise the migrate race.
func TestConcurrentOpenOfNewProject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sluice")
	key := newKey(t)

	const openers = 8
	start := make(chan struct{})
	errs := make(chan error, openers)
	for range openers {
		go func() {
			<-start
			s, err := Open(path, key)
			if err == nil {
				err = s.Close()
			}
			errs <- err
		}()
	}
	close(start)
	for range openers {
		if err := <-errs; err != nil {
			t.Errorf("Open: %v", err)
		}
	}

	s := openStore(t, path, key)
	insertSample(t, s)
}
