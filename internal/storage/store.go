// Package storage is Sluice's encrypted project store: one SQLite file per
// project, encrypted at rest with the Adiantum VFS from ncruces/go-sqlite3.
//
// How the encryption works: SQLite never touches the disk directly; it goes
// through a VFS (virtual file system) layer. The "adiantum" VFS wraps the
// normal OS VFS and encrypts every 4 KiB block on its way to disk and decrypts
// it on the way back. That covers the main database file, the WAL and the
// rollback journal. SQLite itself only ever sees plaintext pages, so every
// SQLite feature (indexes, WAL, transactions) works unchanged.
//
// Threat model (SPEC.md, Storage): protects a copied or stolen file. Adiantum
// is length-preserving and deterministic, so it does not detect tampering and
// an observer of several snapshots can tell which blocks changed.
package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"

	// Importing the package registers the "adiantum" VFS by name, which the
	// DSN selects with ?vfs=adiantum.
	_ "github.com/ncruces/go-sqlite3/vfs/adiantum"
)

// KeySize is the database key length. The default Adiantum construction takes
// a 256-bit key; we generate it with crypto/rand, so no KDF is involved.
const KeySize = 32

// fileMode is the permission for the database and its sidecar files:
// readable and writable by the owner only.
const fileMode os.FileMode = 0o600

// setupTimeout bounds the PRAGMAs and migration that run inside Open.
const setupTimeout = 30 * time.Second

// schemaVersion is stored in PRAGMA user_version once every migration has
// run. It equals len(migrations).
const schemaVersion = 2

//go:embed schema.sql
var schemaSQL string

// migrations[i] takes a database from user_version i to i+1. Entries are
// append-only: a shipped step is never edited, because files already at a
// later version would never run the edited text.
//
//   - 0 -> 1: the M0 schema (schema.sql).
//   - 1 -> 2: M2 adds exchanges.error, the proxy-side failure text.
//     SQLite's ALTER TABLE ADD COLUMN only rewrites the schema entry, not the
//     rows: existing rows read the new column as NULL, so this is cheap even
//     on a large history.
var migrations = []string{
	schemaSQL,
	`ALTER TABLE exchanges ADD COLUMN error TEXT;`,
}

var (
	// ErrInvalidKey means the key is not exactly KeySize bytes.
	ErrInvalidKey = fmt.Errorf("storage: key must be exactly %d bytes", KeySize)

	// ErrWrongKey means the file could not be decrypted into a valid SQLite
	// database: either the key is wrong or the file is not a Sluice project.
	// Adiantum has no MAC, so these two cases look identical: decryption
	// "succeeds" and yields random bytes, which SQLite rejects because page 1
	// lacks the "SQLite format 3" header (SQLITE_NOTADB).
	ErrWrongKey = errors.New("storage: wrong key or not a Sluice project file")

	// ErrNotFound means no row matched.
	ErrNotFound = errors.New("storage: not found")

	// ErrSymlink means the project path is a symbolic link. Following it would
	// create, chmod and write whatever file the link points at.
	ErrSymlink = errors.New("storage: project path is a symbolic link")
)

// Store is an open, encrypted project database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the encrypted project database at path.
//
// The key is applied with PRAGMA hexkey on every pooled connection and never
// appears in the DSN/URI, in a file, or in returned errors.
func Open(path string, key []byte) (*Store, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("storage: resolve path: %w", err)
	}
	if err := createPrivateFile(abs); err != nil {
		return nil, err
	}

	// driver.Open's first callback runs on EVERY new connection that
	// database/sql's pool opens, right after sqlite3_open and before the
	// connection is handed out. That is the only safe place for the key: the
	// pool opens connections lazily and at any time (after idle close, under
	// concurrency), and a connection without the key would see an "empty"
	// database. Running the PRAGMA once on db.Exec would only key whichever
	// single connection happened to run it.
	db, err := driver.Open(buildDSN(abs), connInit(hex.EncodeToString(key)))
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}

	s := &Store{db: db, path: abs}
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	if err := s.setup(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes every pooled connection. With WAL, the last connection to
// close checkpoints the WAL back into the main file and removes it.
func (s *Store) Close() error {
	return s.db.Close()
}

// buildDSN builds the SQLite URI. It carries only non-secret parameters:
//   - vfs=adiantum selects the encrypting VFS.
//   - modeof=<db path> makes the VFS copy the database file's permission bits
//     (0600) onto the journal and WAL files it creates, instead of the
//     umask-derived default (usually 0644).
//
// The key is deliberately NOT a URI parameter (hexkey=...): URI parameters
// are readable by any code holding the connection (sqlite3_uri_parameter,
// vfs.Filename.URIParameters) and tend to end up in logs and error messages.
func buildDSN(abs string) string {
	q := url.Values{}
	q.Set("vfs", "adiantum")
	q.Set("modeof", abs)
	// url.Values.Encode writes a space as "+" (HTML form encoding), but SQLite
	// URIs follow RFC 3986 and only decode %XX, so "Application Support" would
	// become a path with a literal "+". A real "+" is already escaped as %2B,
	// so swapping "+" for %20 is safe.
	rawQuery := strings.ReplaceAll(q.Encode(), "+", "%20")
	u := url.URL{Scheme: "file", OmitHost: true, Path: abs, RawQuery: rawQuery}
	return u.String()
}

// connInit returns the per-connection hook. Order matters: the key must be
// set before anything reads the file. Until then the Adiantum VFS reports the
// file header as empty, so opening without a key does not fail early.
func connInit(hexKey string) func(*sqlite3.Conn) error {
	return func(c *sqlite3.Conn) error {
		// hexKey is [0-9a-f]{64}, so quoting it in SQL text is injection-safe.
		if err := c.Exec("PRAGMA hexkey='" + hexKey + "'"); err != nil {
			return redactedErr("apply database key", err)
		}
		// Temp files (sorts, temp tables, large intermediate results) can hold
		// plaintext copies of rows. Adiantum would encrypt them with a random
		// key, but keeping them in RAM avoids both the disk and that cost.
		if err := c.Exec("PRAGMA temp_store = memory"); err != nil {
			return fmt.Errorf("storage: temp_store: %w", err)
		}
		// Foreign keys are off by default in SQLite and are per-connection.
		if err := c.Exec("PRAGMA foreign_keys = ON"); err != nil {
			return fmt.Errorf("storage: foreign_keys: %w", err)
		}
		return nil
	}
}

// redactedErr keeps only the SQLite result code. A *sqlite3.Error exposes the
// failing statement via SQL(), and for the key PRAGMA that statement contains
// the key, so the original error must not escape.
func redactedErr(op string, err error) error {
	var code sqlite3.ErrorCode
	if errors.As(err, &code) {
		return fmt.Errorf("storage: %s: %w", op, code)
	}
	return fmt.Errorf("storage: %s failed", op)
}

// createPrivateFile creates the database file with mode 0600 before SQLite
// opens it. SQLite treats an empty file as a new database. Chmod also
// tightens a pre-existing file whose mode was loosened.
//
// A symlink as the final path component is rejected (directories along the
// path may be links, as with O_NOFOLLOW). os.OpenFile follows links, so it
// is checked twice: Lstat before opening refuses an existing link without
// side effects, and comparing the opened file with a fresh Lstat afterwards
// catches a link swapped in between, before Chmod can touch the target.
// SQLite then reopens the path by name, so a swap after this check is not
// covered; the defence is that the project directory is the user's own.
func createPrivateFile(abs string) error {
	if err := rejectSymlink(abs); err != nil {
		return err
	}
	// G304: the path is the caller's chosen project file; opening it is the point.
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, fileMode) //nolint:gosec // G304: see above
	if err != nil {
		return fmt.Errorf("storage: create file: %w", err)
	}
	if err := checkOpenedIsPath(f, abs); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(fileMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("storage: chmod file: %w", err)
	}
	return f.Close()
}

// rejectSymlink returns ErrSymlink if abs is a symbolic link. A missing file
// is fine: Open creates it.
func rejectSymlink(abs string) error {
	info, err := os.Lstat(abs)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("storage: stat file: %w", err)
	case info.Mode()&os.ModeSymlink != 0:
		return ErrSymlink
	}
	return nil
}

// checkOpenedIsPath verifies that f is the regular file named by abs itself,
// not a link target: Lstat describes the directory entry without following
// it, f.Stat describes what was actually opened, and os.SameFile compares
// their device and inode numbers.
func checkOpenedIsPath(f *os.File, abs string) error {
	opened, err := f.Stat()
	if err != nil {
		return fmt.Errorf("storage: stat file: %w", err)
	}
	entry, err := os.Lstat(abs)
	if err != nil {
		return fmt.Errorf("storage: stat file: %w", err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, entry) {
		return ErrSymlink
	}
	return nil
}

func (s *Store) setup(ctx context.Context) error {
	// journal_mode is persistent (stored in the file header), so setting it
	// once per Open is enough. SQLite answers with the mode actually in
	// effect; it silently stays in the old mode if WAL is unavailable (for
	// example, no shared-memory support in the VFS), so check the answer.
	//
	// Switching a new file to WAL needs an exclusive lock. If two processes
	// open the same new project, each holds a shared lock while asking to
	// upgrade, and SQLite fails one with SQLITE_BUSY at once instead of
	// waiting (waiting would deadlock). That BUSY is meant to be retried.
	var mode string
	err := retryBusy(ctx, func() error {
		return s.db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&mode)
	})
	if err != nil {
		return classify("set journal_mode", err)
	}
	if mode != "wal" {
		return fmt.Errorf("storage: journal_mode is %q, want \"wal\"", mode)
	}
	if err := s.migrate(ctx); err != nil {
		return classify("migrate", err)
	}
	return s.tightenSidecars()
}

// retryBusy runs op until it returns something other than SQLITE_BUSY,
// backing off exponentially (1 ms doubling to 100 ms) until ctx is done.
func retryBusy(ctx context.Context, op func() error) error {
	const maxDelay = 100 * time.Millisecond
	delay := time.Millisecond
	for {
		err := op()
		if !errors.Is(err, sqlite3.BUSY) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
		delay = min(2*delay, maxDelay)
	}
}

// tightenSidecars sets 0600 on the -wal and -shm files. modeof (see
// buildDSN) covers the WAL, but the -shm (wal-index) file is created by a
// separate code path that ignores it. The -shm file holds only the WAL index
// (page numbers and checksums, no row data), but we keep it private anyway.
//
// Residual window: between SQLite creating -shm and this chmod, -shm has the
// umask-derived mode (usually 0644). Closing it would mean lowering the umask
// with syscall.Umask, but the umask is process-wide, not per-goroutine: in a
// multi-goroutine app it would also change files created concurrently
// elsewhere, and restoring it races with other callers. Since -shm carries no
// row data, a short window of world-readable page numbers is accepted.
func (s *Store) tightenSidecars() error {
	for _, suffix := range []string{"-wal", "-shm"} {
		err := os.Chmod(s.path+suffix, fileMode)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("storage: chmod %s: %w", suffix, err)
		}
	}
	return nil
}

// migrate brings the database up to schemaVersion by running every pending
// step of migrations, all in one transaction.
//
// The version check and the steps must be one atomic unit, or two processes
// opening the same project could both see the old user_version and both run
// the steps. A default ("deferred") transaction takes no lock until its first
// write, which leaves exactly that gap. LevelSerializable makes the ncruces
// driver issue BEGIN IMMEDIATE instead, which takes the write lock up front:
// the second opener waits (busy timeout) until the first commits, then reads
// the new user_version and finds nothing to do.
//
// SQLite DDL is transactional, so a failed step rolls back the earlier ones
// too and the file stays at its old version.
func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	switch {
	case version == schemaVersion:
		return nil
	case version > schemaVersion:
		return fmt.Errorf("schema version %d is newer than supported %d", version, schemaVersion)
	}

	for v := version; v < schemaVersion; v++ {
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			return fmt.Errorf("step %d->%d: %w", v, v+1, err)
		}
	}
	// PRAGMA does not accept bound parameters; schemaVersion is a constant.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// classify turns SQLITE_NOTADB into ErrWrongKey; see ErrWrongKey for why a
// wrong key surfaces as "not a database".
func classify(op string, err error) error {
	if errors.Is(err, sqlite3.NOTADB) {
		return ErrWrongKey
	}
	return fmt.Errorf("storage: %s: %w", op, err)
}
