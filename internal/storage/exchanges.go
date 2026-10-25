package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Message is one side of an exchange, stored as captured (secrets included;
// redaction happens on paths that leave the store, not here).
type Message struct {
	RawHeaders    []byte // head as received: start line through the blank line
	RawBody       []byte // body as on the wire (chunk framing included), capped
	BodyTruncated bool   // RawBody was cut at MaxStoredBody; forwarding was not
}

// Exchange is one request/response pair as stored.
type Exchange struct {
	// ID is the row id. Zero lets SQLite pick one; the app passes its own so
	// the grid row and the stored row share an id before the write lands.
	ID        int64
	StartedAt time.Time // stored as unix milliseconds
	Duration  time.Duration
	Scheme    string
	Host      string
	Port      int
	Method    string
	Path      string
	Status    int    // 0 when no response was sent
	ReqSize   int64  // decoded request body bytes forwarded
	RespSize  int64  // decoded response body bytes forwarded
	Err       string // proxy-side failure, empty on success
	Tool      string
	IsLLM     bool
	LLMReason string   // which detection rules matched, e.g. "path,sse"; empty if none
	Request   *Message // nil if not captured
	Response  *Message // nil if not captured
}

const (
	kindRequest  = "request"
	kindResponse = "response"
)

// InsertExchange stores ex and its messages in one transaction and returns
// the exchange ID.
func (s *Store) InsertExchange(ctx context.Context, ex Exchange) (int64, error) {
	var id int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = insertTx(ctx, tx, ex)
		return err
	})
	return id, err
}

// InsertBatch stores every exchange in one transaction: either all of them
// land or none do. One transaction per batch, instead of one per row, is what
// makes the single storage writer keep up: each commit is a WAL append plus
// (by default) an fsync, so committing 256 rows at once costs about the same
// as committing one.
func (s *Store) InsertBatch(ctx context.Context, batch []Exchange) error {
	if len(batch) == 0 {
		return nil
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for i := range batch {
			if _, err := insertTx(ctx, tx, batch[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage: commit: %w", err)
	}
	return nil
}

func insertTx(ctx context.Context, tx *sql.Tx, ex Exchange) (int64, error) {
	// A nil id binds as NULL, and inserting NULL into an INTEGER PRIMARY KEY
	// column makes SQLite assign the next rowid.
	var id any
	if ex.ID != 0 {
		id = ex.ID
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO exchanges (id, started_at, duration_ms, scheme, host, port, method, path,
		                        status, req_size, resp_size, error, tool, is_llm, llm_reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ex.StartedAt.UnixMilli(), ex.Duration.Milliseconds(), ex.Scheme, ex.Host, ex.Port,
		ex.Method, ex.Path, ex.Status, ex.ReqSize, ex.RespSize, nullIfEmpty(ex.Err), ex.Tool, ex.IsLLM, nullIfEmpty(ex.LLMReason))
	if err != nil {
		return 0, fmt.Errorf("storage: insert exchange: %w", err)
	}
	newID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("storage: exchange id: %w", err)
	}

	for _, part := range []struct {
		kind string
		m    *Message
	}{{kindRequest, ex.Request}, {kindResponse, ex.Response}} {
		if part.m == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO messages (exchange_id, kind, raw_headers, raw_body, body_truncated) VALUES (?, ?, ?, ?, ?)`,
			newID, part.kind, nonNil(part.m.RawHeaders), part.m.RawBody, part.m.BodyTruncated); err != nil {
			return 0, fmt.Errorf("storage: insert %s: %w", part.kind, err)
		}
	}
	return newID, nil
}

// exchangeColumns is the metadata column list shared by every exchange query;
// scanExchange reads them in this order.
const exchangeColumns = `id, started_at, COALESCE(duration_ms, 0), scheme, host, port, method, path,
	COALESCE(status, 0), COALESCE(req_size, 0), COALESCE(resp_size, 0), COALESCE(error, ''),
	tool, COALESCE(is_llm, 0), COALESCE(llm_reason, '')`

type scanner interface{ Scan(dest ...any) error }

func scanExchange(r scanner) (Exchange, error) {
	var ex Exchange
	var startedMs, durMs int64
	if err := r.Scan(&ex.ID, &startedMs, &durMs, &ex.Scheme, &ex.Host, &ex.Port, &ex.Method, &ex.Path,
		&ex.Status, &ex.ReqSize, &ex.RespSize, &ex.Err, &ex.Tool, &ex.IsLLM, &ex.LLMReason); err != nil {
		return Exchange{}, err
	}
	ex.StartedAt = time.UnixMilli(startedMs)
	ex.Duration = time.Duration(durMs) * time.Millisecond
	return ex, nil
}

// GetExchange loads one exchange and its messages. It returns ErrNotFound if
// id does not exist.
func (s *Store) GetExchange(ctx context.Context, id int64) (Exchange, error) {
	ex, err := scanExchange(s.db.QueryRowContext(ctx,
		`SELECT `+exchangeColumns+` FROM exchanges WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Exchange{}, ErrNotFound
	}
	if err != nil {
		return Exchange{}, fmt.Errorf("storage: get exchange: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT kind, raw_headers, raw_body, COALESCE(body_truncated, 0) FROM messages WHERE exchange_id = ?`, id)
	if err != nil {
		return Exchange{}, fmt.Errorf("storage: get messages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kind string
		var m Message
		if err := rows.Scan(&kind, &m.RawHeaders, &m.RawBody, &m.BodyTruncated); err != nil {
			return Exchange{}, fmt.Errorf("storage: scan message: %w", err)
		}
		switch kind {
		case kindRequest:
			ex.Request = &m
		case kindResponse:
			ex.Response = &m
		default:
			return Exchange{}, fmt.Errorf("storage: unknown message kind %q", kind)
		}
	}
	if err := rows.Err(); err != nil {
		return Exchange{}, fmt.Errorf("storage: read messages: %w", err)
	}
	return ex, nil
}

// RecentExchanges returns metadata (no messages) for the newest limit
// exchanges with id <= maxID, oldest first, which is the order the grid
// appends in. It reads only the small exchanges table. The maxID bound lets
// the app load "history before this session" without racing the rows the
// live path is adding at the same time.
func (s *Store) RecentExchanges(ctx context.Context, limit int, maxID int64) ([]Exchange, error) {
	if limit <= 0 {
		return nil, nil
	}
	// The inner query walks the rowid index backwards (cheap), the outer one
	// flips the window back to ascending order.
	rows, err := s.db.QueryContext(ctx,
		`SELECT * FROM (SELECT `+exchangeColumns+` FROM exchanges WHERE id <= ? ORDER BY id DESC LIMIT ?) ORDER BY id`, maxID, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: recent exchanges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Exchange
	for rows.Next() {
		ex, err := scanExchange(rows)
		if err != nil {
			return nil, fmt.Errorf("storage: scan exchange: %w", err)
		}
		out = append(out, ex)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: read exchanges: %w", err)
	}
	return out, nil
}

// MaxID returns the largest exchange id, or 0 for an empty project. The app
// starts its id counter here so new rows never collide with stored ones.
func (s *Store) MaxID(ctx context.Context) (int64, error) {
	var id int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM exchanges`).Scan(&id); err != nil {
		return 0, fmt.Errorf("storage: max id: %w", err)
	}
	return id, nil
}

// CountExchanges returns the number of stored exchanges.
func (s *Store) CountExchanges(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM exchanges`).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count exchanges: %w", err)
	}
	return n, nil
}

// nonNil maps a nil slice to an empty one: raw_headers is NOT NULL, and a nil
// []byte binds as SQL NULL.
func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
