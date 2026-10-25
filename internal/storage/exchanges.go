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
	RawHeaders []byte
	RawBody    []byte
}

// Exchange is one request/response pair. Only the columns M0 needs are mapped;
// the rest of the exchanges table keeps its schema defaults.
type Exchange struct {
	ID        int64
	StartedAt time.Time // stored as unix milliseconds
	Scheme    string
	Host      string
	Port      int
	Method    string
	Path      string
	Tool      string
	Request   *Message // nil if not captured
	Response  *Message // nil if not captured
}

const (
	kindRequest  = "request"
	kindResponse = "response"
)

// InsertExchange stores ex and its messages in one transaction and returns
// the new exchange ID.
func (s *Store) InsertExchange(ctx context.Context, ex Exchange) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("storage: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO exchanges (started_at, scheme, host, port, method, path, tool)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ex.StartedAt.UnixMilli(), ex.Scheme, ex.Host, ex.Port, ex.Method, ex.Path, ex.Tool)
	if err != nil {
		return 0, fmt.Errorf("storage: insert exchange: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("storage: exchange id: %w", err)
	}

	for kind, m := range map[string]*Message{kindRequest: ex.Request, kindResponse: ex.Response} {
		if m == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO messages (exchange_id, kind, raw_headers, raw_body) VALUES (?, ?, ?, ?)`,
			id, kind, nonNil(m.RawHeaders), m.RawBody); err != nil {
			return 0, fmt.Errorf("storage: insert %s: %w", kind, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("storage: commit: %w", err)
	}
	return id, nil
}

// GetExchange loads one exchange and its messages. It returns ErrNotFound if
// id does not exist.
func (s *Store) GetExchange(ctx context.Context, id int64) (Exchange, error) {
	ex := Exchange{ID: id}
	var startedMs int64
	err := s.db.QueryRowContext(ctx,
		`SELECT started_at, scheme, host, port, method, path, tool FROM exchanges WHERE id = ?`, id).
		Scan(&startedMs, &ex.Scheme, &ex.Host, &ex.Port, &ex.Method, &ex.Path, &ex.Tool)
	if errors.Is(err, sql.ErrNoRows) {
		return Exchange{}, ErrNotFound
	}
	if err != nil {
		return Exchange{}, fmt.Errorf("storage: get exchange: %w", err)
	}
	ex.StartedAt = time.UnixMilli(startedMs)

	rows, err := s.db.QueryContext(ctx,
		`SELECT kind, raw_headers, raw_body FROM messages WHERE exchange_id = ?`, id)
	if err != nil {
		return Exchange{}, fmt.Errorf("storage: get messages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kind string
		var m Message
		if err := rows.Scan(&kind, &m.RawHeaders, &m.RawBody); err != nil {
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

// nonNil maps a nil slice to an empty one: raw_headers is NOT NULL, and a nil
// []byte binds as SQL NULL.
func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
