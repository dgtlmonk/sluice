-- Schema version 1 (SPEC.md, Storage). Applied once by migrate() inside a
-- transaction; PRAGMA user_version records that it ran.

CREATE TABLE exchanges (
  id             INTEGER PRIMARY KEY,
  started_at     INTEGER NOT NULL,      -- unix ms
  duration_ms    INTEGER,
  scheme         TEXT NOT NULL,         -- http | https | ws | wss
  host           TEXT NOT NULL,
  port           INTEGER NOT NULL,
  method         TEXT NOT NULL,
  path           TEXT NOT NULL,
  status         INTEGER,
  req_size       INTEGER,
  resp_size      INTEGER,
  mime           TEXT,
  tool           TEXT NOT NULL,         -- proxy | repeater | fuzzer | ai
  is_llm         INTEGER DEFAULT 0,     -- flagged by LLM detector
  has_tool_calls INTEGER DEFAULT 0,     -- response contained tool/function calls
  in_scope       INTEGER DEFAULT 1,
  notes          TEXT
);

CREATE TABLE messages (
  exchange_id    INTEGER NOT NULL REFERENCES exchanges(id),
  kind           TEXT NOT NULL,         -- request | response
  raw_headers    BLOB NOT NULL,
  raw_body       BLOB,
  body_truncated INTEGER DEFAULT 0,     -- stored copy cut at 32 MB
  PRIMARY KEY (exchange_id, kind)
);

CREATE TABLE ws_frames (
  id             INTEGER PRIMARY KEY,
  exchange_id    INTEGER NOT NULL REFERENCES exchanges(id),
  at             INTEGER NOT NULL,
  direction      TEXT NOT NULL,         -- client | server
  opcode         INTEGER NOT NULL,
  payload        BLOB
);

CREATE TABLE findings (
  id             INTEGER PRIMARY KEY,
  exchange_id    INTEGER REFERENCES exchanges(id),
  source         TEXT NOT NULL,         -- passive | canary | regex | promptfoo | garak | manual
  rule           TEXT NOT NULL,         -- e.g. missing-hsts, LLM01
  severity       TEXT NOT NULL,         -- info | low | medium | high
  confidence     TEXT NOT NULL,         -- confirmed | probable | sink-unverified
  title          TEXT NOT NULL,
  evidence       TEXT,
  created_at     INTEGER NOT NULL
);

CREATE INDEX ix_exchanges_host ON exchanges(host);
CREATE INDEX ix_exchanges_started ON exchanges(started_at);
