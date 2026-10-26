# Sluice — Build Spec

Oct 24, 2026 · Joel · rev 2 (stack decided, review fixes applied)

## Overview

A learning build of a Burp-style intercepting proxy: a native desktop app with a React UI in a webview and a Go engine. macOS first, cross-platform later. Name: **Sluice**.

Learning goals:

- How HTTP/1.1, TLS, and later HTTP/2 actually work on the wire
- How TLS interception works: a local root CA and per-host certificates
- Building a responsive desktop UI over high-volume live data
- Testing LLM-powered apps for prompt injection and related risks

Non-goals: competing with Burp, HTTP/3 (transparent-only and blocked by ECH), a cloud or team mode, and testing anything outside the scope rules below.

Working rules for Claude Code live in [CLAUDE.md](CLAUDE.md).

## Decisions

| Decision | Outcome |
| --- | --- |
| Engine | **Go** (decided 2026-10-24). `crypto/tls` hooks (`GetCertificate`, `NextProtos`) map directly onto the intercept layer |
| Shell + UI | **Wails** + React + TypeScript (Vite) |
| Encryption at rest | **v1** (decided 2026-10-24). Secrets are stored encrypted, not redacted, so replaying old authenticated requests works after a restart |
| Encrypted SQLite | **`ncruces/go-sqlite3` + `vfs/adiantum`** (decided 2026-10-24). Maintained, current SQLite, no extra native library to link or ship. SQLCipher was rejected: the Go SQLCipher fork is stale, and self-linking SQLCipher means owning a fragile native build. Trade-off accepted: Adiantum encrypts but does not detect tampering |
| HTTP/2 | Offer only `http/1.1` via ALPN from M3; tunnel h2-only clients and hosts raw; real HTTP/2 at M8 |
| Reference oracle | `net/http` allowed from day 1 in tests only (including differential fuzzing), never in the traffic path. If the hand-rolled parser stalls past M3, drop the no-library rule |
| MCP server | After M6, stdio, read-only. Active tools at M8, behind scope tests and UI confirm |
| Claude assistant | After M8. Off by default, consent per send, captured content treated as untrusted |
| AI module v1 | Lean: detection (incl. `tool_calls`, SSE), canary + regex, payload library, usage counters. No OWASP coverage claim; a coverage matrix marks each item tested, partial or none |
| LLM detection | Basic passive flagging pulled forward to M2 (paths, JSON shape, SSE content type). Deep detection stays at M6 |
| WebSockets | M5, passthrough + frame viewer, before the AI module |
| Match-and-replace | M4 |
| Intruder attack types | Sniper + cluster bomb in M5; the rest at M8 |
| Pinning detection | M3, passive, only when the CA trust check passes |
| Project focus | Security testing and defense (blue team): find leaks and weaknesses; record defender-visible signals such as the JA4 TLS fingerprint |
| mTLS client certs, session macros | After M8 |
| OOB interaction server | M7, self-hosted, scope-bound |

Background: a six-person review panel first voted for .NET + Avalonia. A later review moved the stack to a React webview plus a systems-language engine, because the UI is the strongest existing skill and Go signals more for a security pivot. Burp is Java, so the language is secondary to the protocol and UX work.

Fact-checked points that still matter: leaf certs use about 397 days validity; the 2026 OWASP LLM list uses its new category names; real HTTPS sites don't need HTTP/2 because browsers fall back to HTTP/1.1 when the proxy offers only that.

## Tech stack

| Layer | Choice | Notes |
| --- | --- | --- |
| UI | React + TypeScript (Vite) | The strongest layer |
| Shell | Wails | Native binary + OS webview (WebKit on macOS). Wails uses CGo on macOS |
| History grid | TanStack Table + TanStack Virtual | Row virtualization; page data from the engine in windows. M0 go/no-go |
| Editor | CodeMirror 6 | Raw/Pretty request + response, large payloads, highlighting |
| Hex view | Custom React component | Virtualized rows; nothing good off-the-shelf |
| Layout | react-resizable-panels, Radix UI | Split panes; unstyled tab/menu/dialog primitives |
| Frontend state | Zustand | Drains a batched event buffer from the engine (~100 ms) |
| Engine | Go | Single binary; headless engine packages, no UI imports |
| TLS / sockets | `net`, `crypto/tls`, `crypto/x509` | Hand-rolled HTTP/1.1; ALPN pinned to `http/1.1` |
| Certificates | `crypto/x509` | One RSA 2048 root CA + per-host leaf certs sharing one leaf key |
| Storage | SQLite via `github.com/ncruces/go-sqlite3` + `vfs/adiantum` | Encrypted at rest. Behind a store interface |
| Secrets | macOS Keychain | CA key passphrase and the 32-byte database key |
| Test oracle | `net/http`, `httptest`, `go test -fuzz` | Tests only: diff the hand-rolled parser against it. Never in the traffic path |
| CI | GitHub Actions: `go vet`, `govulncheck`, `golangci-lint`, `go test` | From the first commit |
| HTTP/2 (M8) | Own framing + HPACK (reference: `golang.org/x/net/http2`) | h2-only traffic bypassed until then |
| AI tooling | promptfoo (M7), garak (M7) | Subprocesses, pinned; garak in its own uv/venv |
| MCP (after M6) | `mark3labs/mcp-go`, stdio | Read-only tools first |

## Architecture

The engine knows nothing about the UI. It publishes events through two separate paths:

- **Storage path (lossless):** a dedicated bounded queue drained in batches by the single storage writer. History must not silently lose rows. If this queue ever fills, forwarding still does not block; the exchange is marked unsaved and a "history incomplete" error shows in the UI. That state is a bug to fix, not normal operation.
- **Live path (lossy):** a bounded channel feeding the UI and the AI module. On overflow it drops the event and increments a dropped-event counter shown in the status bar. The UI can always re-read missed rows from storage.

```
sluice/
  main.go, app.go      # Wails entry point and bindings
  frontend/            # React app (Wails convention)
  internal/
    engine/            # listener, HTTP/1.1 parser, TLS MITM, CA, pipeline, scope
    storage/           # encrypted SQLite, schema, batch writer, queries
    platform/          # Keychain, cert trust, system proxy, browser launcher (macOS)
    ai/                # LLM detector, payload library, scanner runners
    mcp/               # MCP server (stdio)
    testorigin/        # local test origin for integration tests
  payloads/            # YAML payload sets
```

## Proxy engine

The engine is headless: it accepts connections, runs each exchange through a pipeline, and publishes events. It never imports UI code.

**Listener**

- Explicit proxy on `127.0.0.1:8080` (configurable). Bind to loopback only by default.
- One goroutine per client connection; `bufio.Reader` for parsing.

**HTTP/1.1**

- Parse request line, headers, and body: `Content-Length`, `Transfer-Encoding: chunked`, and connection-close bodies.
- Reject ambiguous framing, because a proxy that accepts it can be used for request smuggling:
  - both `Content-Length` and `Transfer-Encoding` present
  - multiple differing `Content-Length` values
  - a `Transfer-Encoding` whose final coding is not `chunked`
  - obsolete line folding in headers
  - bare `CR` or `LF` where `CRLF` is required
- Enforce limits: request line length, header count, and total header size. Reject with `400` / `431` when exceeded.
- Stream bodies through as they arrive; never buffer a whole chunked or SSE body before forwarding, or LLM token streaming breaks.
- Absolute-form URIs for plain HTTP; origin-form inside tunnels.
- Keep-alive on both legs; a simple upstream connection pool keyed by host:port:tls.
- Decompress gzip/deflate/br for display only; forward the original bytes unless the user edits the body.
- Keep raw bytes for every message. The UI shows parsed views, but replay uses raw.
- Differential fuzzing: `go test -fuzz` feeds the same bytes to this parser and to `net/http`; any disagreement in accept/reject or parsed fields is a finding.

**HTTPS (CONNECT + MITM)**

The bypass decision must happen before the TLS handshake with the client, so the order matters:

1. Client sends `CONNECT host:443`; reply `200 Connection Established`.
2. Peek the ClientHello without consuming it. Read SNI (fall back to the CONNECT host) and the client's ALPN list.
3. Decide bypass. Tunnel raw, replaying the peeked bytes, when any of these is true:
   - the host is on the user bypass list or the pinned list
   - the client offers only `h2` (gRPC and other h2-only clients)
   - the host is already known to be h2-only
4. Dial the origin with TLS offering only `http/1.1`. If the origin refuses (no ALPN overlap), mark the host h2-only and tunnel this connection raw.
5. Get or mint a leaf cert for the host, signed by the root CA. Cache in memory and on disk.
6. Finish the client handshake with the minted leaf (`GetCertificate`), advertising only `http/1.1`.
7. Run the normal HTTP/1.1 pipeline inside the decrypted tunnel.

Pinning detection: when the client aborts the handshake right after receiving the leaf cert, flag "pinning suspected" for that host and offer to add it to the bypass list. Only raise this flag when the CA trust health check passes; an untrusted CA causes the same abort.

**Root CA**

- RSA 2048, 10-year validity, `CA:true` basic constraint, generated on first run. One algorithm, one code path.
- Leaf certs: SAN = host, about 397 days validity, random serial, SKI/AKI set, `serverAuth` EKU. That passes both of Apple's limits: 825 days for user-added roots and 398 days for public roots.
- All leaf certs share one leaf key pair, generated once and stored with the CA. Only the certificate is minted per host. Measured at M3 (Apple M3 Max, go1.26.10, `-count=5`): minting with the shared key takes about 0.94 ms (±5%); a fresh RSA 2048 key per host takes about 48 ms (sd 10%, 52x slower), so per-host RSA keys would stall a page with many hosts. A fresh ECDSA P-256 key per host costs about the same as the shared key (0.90 ms), because the root's RSA signature dominates. A leaf-cache hit takes about 94 ns. Keep the shared key.
- CA private key stored in the per-user app data folder, mode 0600, encrypted with a passphrase kept in the macOS Keychain. Never log or export it except via an explicit "Export CA" action.

**Pipeline**

- Stages: OnRequest → scope check → match-and-replace → intercept hold (optional) → forward → OnResponse → match-and-replace → intercept hold (optional) → publish.
- Traffic never waits on observers (see Architecture for the two event paths).
- Intercept holds are channels the UI completes with forward / edit / drop. Each hold has a timeout and a `context` cancellation tied to shutdown, and releases its pooled upstream connection on abort.
- Scope is enforced here, in the engine, for every active send, redirect hop and resolved IP. The UI only displays it.
- Match-and-replace (M4): ordered regex rules on request/response headers and bodies, each rule toggleable.

**Later**

- WebSockets (M5): capture text and binary frames after the `101` upgrade, with a frame viewer. Frame editing and replay come later.
- HTTP/2 (M8): own framing and HPACK as a learning exercise, or a library. Until then, h2-only traffic is tunnelled raw.
- After M8: upstream proxy and SOCKS, mTLS client certs per host, session macros.

## UI (React + webview)

One window: a React app in a webview, with a tab per tool. The engine exposes typed Wails bindings to the frontend and pushes batched events through Wails events. Dark theme by default.

| Tab | Purpose | Key components |
| --- | --- | --- |
| Proxy / History | Every captured exchange; filter, search, select | TanStack Table + Virtual (method, host, path, status, length, MIME, time, LLM flag); filter bar; request/response split view; WebSocket frames sub-tab (M5) |
| Intercept | Hold, edit, forward, or drop the next request/response | Toggle, CodeMirror editor, Forward / Drop, queue count, hold timeout; match-and-replace rules editor (M4) |
| Repeater | Edit and resend one request, compare responses | Tabs per saved request, CodeMirror editor, Send, response view with timing |
| Fuzzer | Payload positions, payload lists, results table | Position markers (`§…§`), sniper and cluster-bomb modes, list loader, concurrency + delay settings, results grid sortable by status/length/time |
| Findings | Passive check results and AI scan results | Grid grouped by severity, detail pane with evidence request |
| AI | LLM endpoint list, scanner runs, MCP server status | Endpoint grid, run buttons, live log, report viewer, OWASP coverage matrix (tested / partial / none) |
| Settings | Listener, CA, scope, bypass hosts, browser launch, retention TTL, CA trust health check | Forms; "Export CA" and "Launch browser" actions |

UI rules:

- Message views: Pretty (formatted JSON/HTML/XML) and Raw via CodeMirror, plus Headers and a custom Hex view.
- Large bodies (over 1 MB) load lazily and render truncated with a "load all" action.
- Live updates are batched: the engine flushes an event batch ~every 100 ms; the frontend drains it into a Zustand store, never one render per exchange. The status bar shows dropped live events and any "history incomplete" error.
- Context menu on any request: Send to Repeater, Send to Fuzzer, Copy as curl, Add host to scope.
- Native macOS menu bar via the Wails menu API.

## Feature candidates (from other tools)

Ideas worth copying, collected along the way. Not scheduled; each moves into a milestone only when picked. Focus: security testing and defense, especially background and phone-home traffic.

| Idea | Seen in | Why it matters here |
|------|---------|---------------------|
| Process name per connection (which app made it) — **M3.5** | Little Snitch, LuLu, Proxyman | Background traffic is only useful when you know which app sent it |
| Background traffic view: group by app and host, mark first-seen hosts — **M3.5** | Little Snitch | New phone-home hosts stand out without reading every row |
| Transparent capture for apps that ignore proxy settings (Network Extension or `pf` redirect) — **M9** | mitmproxy (transparent/local mode), Proxyman | Daemons and many CLIs never use the system proxy |
| Import a TLS key log (`SSLKEYLOGFILE`) and decrypt a pcap without MITM | Wireshark | Inspect pinned apps and TLS without a trusted CA in the path |
| Scripting hooks on request/response | mitmproxy addons, Burp extensions | Repeatable custom checks and rewrites |
| Map local / map remote, breakpoints | Charles, Proxyman | Swap a response or edit a request mid-flight |
| Per-app proxy launch helper (start a browser profile pointed at Sluice) | Proxyman | One click instead of a terminal command |

## Optimization backlog

The main goal is functionality. These items are tracked for a later optimization pass, not milestone gates. Goal: memory efficient, with memory flat as history grows.

- **Webview holds only a window:** grid pages windows from the engine; filter and sort move to SQLite (`WHERE` / `ORDER BY`). Until then the client-side filter/sort holds all rows in the webview; Clear resets it.
- **Rows carry no bodies** (already true): the detail pane fetches one exchange on demand.
- **Bounded caches:** upstream connection pool with idle timeout; in-memory leaf-cert cache as an LRU backed by the disk cache.
- **Frontend tooling:** upgrade Vite 3 to a supported major (dev-server advisory GHSA-67mh-4wv8-2f99).
- **Proxy copy path (M1):** pool the 32 KiB copy buffers (`sync.Pool`); coalesce flushes for non-streaming bodies (today every read is flushed so SSE/chunked stream); background reaper for idle upstream conns plus a global idle cap (today: per-host cap, age checked on reuse).
- **Proxy request/response overlap (M1):** request body is fully sent before the response is read; a full-duplex copy would let an origin answer early (e.g. 413) without waiting for a large upload.
- **Pool health peek (M1):** reusing an idle upstream conn does a 1-byte read with a 1 ms deadline while holding the pool mutex; move it outside the lock (or use a non-blocking syscall peek) so concurrent gets do not serialize on it.
- ~~**Proxy row summaries (M2 bridge):**~~ done in M2: the detail pane reads from the store on demand; the in-memory summary map is gone.
- **Storage capture (M2):** request/response bodies are buffered in memory per in-flight exchange (up to the 32 MB cap each) until the exchange finishes, and the queue holds up to 512 MiB of waiting rows. Stream large bodies into SQLite incrementally (blob I/O) instead, and size the queue budget from measurements.
- **Capture lock (M2):** one mutex guards every in-flight capture, so body taps on many connections contend on it; shard by exchange id or keep a per-exchange buffer owned by the connection goroutine.
- **Writer batching (M2):** fixed 256-row batches with a plain fsync per commit; tune batch size/time window and consider `PRAGMA synchronous = NORMAL` under WAL after measuring.
- **LLM detection (M2):** `detect.LLM` runs on the connection goroutine after forwarding, so a large JSON body (up to the 1 MiB cap) delays the next keep-alive request on that connection; it also allocates about 3x the body. Move it to the storage writer or a worker pool, and decode with a streaming token reader.
- **Proxy latency under load (M2):** the M2 load test (`SLUICE_LOAD=1 go test -run TestLoadFull .`, 32 keep-alive clients, mixed framing) runs at ~830 req/s with p50 ~30 ms on loopback; the headless `sluice-proxy` (no storage) shows the same p50, so the cost is in the engine, not capture or storage. Measured cause: the pool health peek (`upstreamConn.quiet` in `internal/engine/pool.go`) blocks for its full 1 ms deadline on every healthy idle conn while holding the pool-wide mutex, so 32 workers on one origin queue ~32 ms and pool gets cap near 1000/s (a scratch run with a 20 µs deadline gave p50 170 µs, ~4000 req/s). Fix: peek outside the lock with a non-blocking `recv(MSG_PEEK|MSG_DONTWAIT)`. Nagle is not involved (Go sets TCP_NODELAY).
- **Leaf cert cache (M3):** minting runs under one mutex for all hosts, so a burst of new hosts signs serially; use a per-host singleflight. The cache is unbounded (see Bounded caches) and only in memory.
- **Upstream TLS (M3):** every new pooled upstream conn does a full TLS handshake; enable client session resumption (`tls.Config.ClientSessionCache`) after measuring handshake cost.
- **CONNECT probe (M3):** every decrypted CONNECT dials and handshakes with the origin before answering the client (to detect origins that refuse http/1.1); the probe conn is pooled, but a client that opens many tunnels still costs one upstream handshake each. Cache "accepts http/1.1" per host with a TTL, or probe in parallel with the client handshake.
- **TLS facts per row (M3):** JA4 / tunnel reason / pinning flag live in an in-memory map in the bridge (capped at 100k rows, FIFO) because schema v1 has no columns for them; move them into the store (schema v2) so they survive restarts and stop costing memory.
- **Learned TLS hosts (M3):** pinned / h2-only flags are in memory only (capped at 4096 hosts); persist them per project.
- **Measure:** engine heap (`runtime.MemStats`) and webview RSS under sustained traffic, e.g. 1M synthetic exchanges.

## Storage

One encrypted SQLite file per project (`*.sluice`), mode 0600, written by a single background writer that drains the storage queue in batches.

**Encryption at rest (v1)**

- Driver: `github.com/ncruces/go-sqlite3` with the `adiantum` VFS. It encrypts the database, journal, WAL and temp files.
- Key: 32 random bytes from `crypto/rand`, created with the project and stored in the macOS Keychain. Never in a file, log, or URI.
- On every connection open, run `PRAGMA hexkey='…'` immediately, then `PRAGMA temp_store = memory`. Do not pass the key as a URI parameter; other code can read URI parameters.
- WAL mode under the adiantum VFS is verified in M0 before the schema depends on it.
- Threat model: protects a copied or stolen file. Adiantum does not detect tampering; someone who can write the file can already do worse on the machine, and captured content is treated as untrusted anyway.

**Secrets**

- Stored as captured, inside the encrypted file, so replay works after a restart.
- Redacted (`Authorization`, `Cookie`, `Set-Cookie`, API-key-shaped values) on every path that leaves the store: logs, exports, Copy as curl (optional toggle), MCP tool output, and anything sent to an LLM.

**Retention**

- 7-day TTL by default, pruned on startup and hourly while running.
- "Wipe project" deletes the file, its `-wal`/`-shm` sidecars, and its Keychain key.

**Bodies**

- All bodies stay inside the encrypted database; no sidecar files, because files outside SQLite would not be encrypted.
- Bodies live in `messages`, so the history grid only reads the small `exchanges` table.
- Stored bodies are capped at 32 MB; beyond that, the stored copy is truncated and flagged. Forwarding is never truncated.

```sql
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
```

The grid pages through `exchanges` in windows (data virtualization) rather than loading all rows. Add an FTS5 table over headers and text bodies once search is needed.

## Platform abstraction

Only these things touch the OS. Each is an interface in `internal/platform`, with only the macOS implementation written now.

| Interface | macOS (now) | Windows (later) | Linux (later) |
| --- | --- | --- | --- |
| Secret store | Keychain (access method decided at M0; see note) | Credential Manager | Secret Service |
| Cert trust store | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db <ca.pem>` (prompts for password); remove with `security delete-certificate` | cert store (Root, CurrentUser) | `update-ca-certificates` / NSS `certutil` |
| System proxy | `networksetup -setwebproxy` / `-setsecurewebproxy` per active service; always restore on exit | WinINet registry keys | gsettings |
| Browser launcher | `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` | `%ProgramFiles%` Chrome path | `google-chrome` / `chromium` |

Keychain note: either a Go Keychain library (a new dependency; ask first) or the `security` CLI. With the CLI, never pass a secret as a command-line argument (`add-generic-password -w <secret>`), because other processes can read process arguments.

Default workflow is the launched browser, not the system proxy:

```
"Google Chrome" --proxy-server=127.0.0.1:8080 \
  --user-data-dir=<app-data>/chrome-profile \
  --no-first-run --no-default-browser-check
```

Only that browser goes through the proxy, so a crash never breaks the rest of the machine's networking. A trust health check on launch confirms the CA is installed and trusted, so a trust problem shows up as a clear message rather than looking like a parser bug. The system proxy is an opt-in setting. Firefox needs the CA imported into its own store or `security.enterprise_roots.enabled` set to true.

## AI security module

The AI module spots LLM traffic in history and attacks those endpoints. v1 makes no OWASP coverage claim: it ships a coverage matrix (tested / partial / none) against the [OWASP Top 10 for LLM Applications 2026](https://cycode.com/blog/owasp-top-10-llm-applications/), the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-application), and the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/). In the 2026 LLM list, prompt injection is #1, sensitive information disclosure #2, and excessive agency #3.

**1. LLM endpoint detection (passive)**

Basic flagging (M2). Flag an exchange as `is_llm` when any of these match:

- Known paths: `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, `/v1/embeddings`, `/api/chat`, `/api/generate` (Ollama)
- Request JSON with `messages[]` (role/content) or `prompt`, plus `model`
- Response `Content-Type: text/event-stream`

Deep detection (M6):

- Reassemble SSE token-delta streams to inspect them
- App-level chat endpoints: JSON field named `message`, `query`, or `question` whose response is long free text (heuristic, lower confidence)
- Record which JSON field carries user input, so attacks know where to inject
- Parse `tool_calls` / function-call fields in responses (the gate for any agentic testing)
- Count tokens and request rate per endpoint (the signal for LLM06 Unbounded Consumption / denial-of-wallet)

**2. Attacks**

In v1 (M6):

- Built-in payload library (YAML), each entry mapped to an OWASP LLM item: direct injection (LLM01), system-prompt / hidden-context extraction (LLM08), sensitive data disclosure (LLM02), output handling (LLM10).
- Canary tokens: plant a unique string in the system prompt of your own test apps; any response containing it is a confirmed leak. For black-box targets (Gandalf), add fuzzy / partial-leak matching.
- Detection: canary match (confirmed), regex rules (probable). Output-handling findings are labelled "model emits X, sink unverified" unless the test app's render path is checked, because LLM10 is about whether the client sink executes the output, not just that the model emits it.

Later milestones:

- Indirect injection via a local server that serves pages with hidden instructions, for RAG and browsing agents (M6.5).
- Multi-turn runs that inject at turn N (M6.5).
- Optional LLM judge as a second, probabilistic signal only (M7). It reads attacker-controlled output, so treat that output as untrusted data, never as instructions to the judge.
- Embeddings / RAG retrieval poisoning (LLM09), memory poisoning, and multimodal injection (post-M8).

**3. External scanners (subprocess)**

- [promptfoo](https://dev.to/ventrova/how-to-test-your-llm-app-for-prompt-injection-promptfoo-vs-garak-vs-giskard-vs-pyrit-vs-2oim) for app-layer tests: generate its config from the captured endpoint (URL, headers, input field) and run `promptfoo redteam`.
- [garak](https://8ksec.io/red-teaming-llm-applications-garak-pyrit/) for model-layer tests: point its REST generator at the endpoint.
- garak and promptfoo arrive at M7, not v1. PyRIT later, for programmable multi-turn attacks.
- Parse each tool's JSON output into `findings`.

**4. MCP server**

Built after M6, not before — shipping an MCP server before the module that tests MCP inverts the learning order. v1 is read-only over stdio. Active tools come later, with scope enforced in the engine and their own tests. If the server is ever offered over HTTP: loopback bind only, a per-session bearer token, and an Origin check (a local token plus Origin check is what stops a malicious web page reaching it by DNS-rebinding).

| Tool | Does | Guard |
| --- | --- | --- |
| `list_exchanges` | Filtered history (host, status, is_llm) | Read-only |
| `get_exchange` | Full raw request/response | Read-only; secrets redacted in output |
| `list_findings` / `add_finding` | Read and record findings | Write to project only |
| `send_request` | Repeater send | In-scope hosts only; rate limited |
| `run_scan` | Start a payload set against an LLM endpoint | In-scope only; UI confirmation required |

**5. Assistant (optional, post-M8)**

Deferred until after M8, off by default, with consent required on each send. All captured content is treated as untrusted input: a captured response can carry a prompt injection aimed at this assistant, so exchange text is passed as clearly delimited data, never as instructions. Redact secrets before sending, log what left the machine, and strip `Authorization` and `Cookie` headers.

## Milestones

Ten milestones, each ending in a working, demoable app. Do them in order; tick the acceptance checks before moving on. v1 is M0–M6; the AI scanners, MCP server and hardening come after.

**M0 — Foundations (week one)**

- [ ] Public repo with `SPEC.md` and `CLAUDE.md`; CI runs `go vet`, `govulncheck`, `golangci-lint` and `go test` on every push
- [ ] Wails + React scaffold builds and opens on macOS
- [ ] Go/no-go: a 100k-row TanStack Virtual table stays smooth on macOS WebKit while a few thousand synthetic events/sec stream in
- [ ] Encrypted store spike: `adiantum` database opens with a Keychain-held key, WAL mode works, and the file is unreadable without the key

**M1 — Plain HTTP proxy (headless)**

- [ ] Local test origin (`internal/testorigin`) serves chunked, Content-Length, keep-alive, connection-close and SSE responses
- [ ] Headless binary forwards HTTP/1.1 through `127.0.0.1:8080`
- [ ] `curl -x http://127.0.0.1:8080 http://localhost:5000/` returns the same bytes as direct
- [ ] Chunked, Content-Length, and keep-alive covered by integration tests against the test origin
- [ ] Ambiguous framing and oversize headers rejected, each with a test
- [ ] Differential fuzz target against `net/http` runs in CI (short run) and locally (long run)

**M2 — History + UI shell**

- [ ] React UI hosts the engine's live event stream; exchanges fill the History grid
- [ ] Selecting a row shows Raw and Headers views
- [ ] Exchanges persist to the encrypted store through the lossless storage queue and reload on restart
- [ ] Basic LLM flag shown in History (paths, JSON shape, SSE content type)
- [ ] 10k requests in a load test keep the UI responsive, with zero storage drops
**M3 — HTTPS interception**

- [x] Root CA generated on first run; Settings can install it to the login keychain and export the PEM; trust health check reports installed/trusted
- [x] CONNECT tunnels decrypted with ALPN forced to http/1.1; launched Chrome loads https://example.com with no warnings
- [x] Bypass list, h2-only clients and h2-only hosts tunnelled raw without decrypting; pinning aborts flagged per host only when the CA is trusted
- [x] Leaf minting time measured with one shared leaf key

**M3.5 — Background traffic (decided 2026-10-25)**

- [ ] Each exchange records the client process (name, PID, bundle ID) by mapping the client's loopback source port to its owning process; the lookup goes through `internal/platform`
- [ ] Background traffic view: exchanges grouped by app, then host; hosts first seen in this project are marked new
- [ ] App and first-seen columns are filterable in History (`app:brave`, `new:true`)

**M4 — Intercept + Repeater**

- [ ] Intercept toggle holds requests (with timeout); edit, forward, and drop all work
- [ ] Send to Repeater; edit and resend; response timing shown
- [ ] Match-and-replace rules apply on request and response
- [ ] Copy as curl

**M5 — Fuzzer + passive checks**

- [ ] Fuzzer: sniper and cluster-bomb modes, list loading, concurrency and delay limits
- [ ] Results sortable by status, length, and time
- [ ] WebSockets: frames captured and shown in a viewer
- [ ] Passive rules: missing security headers, cookie flags, reflected parameters, tokens in URLs
- [ ] Passive leak rules: secrets and API keys in responses or JS, stack traces and version banners, internal IPs and hostnames, PII patterns
- [ ] Hex view for decrypted messages (spots CR/LF, null bytes and look-alike characters behind injection and smuggling bugs)
- [ ] Storage: 7-day TTL with hourly prune, 32 MB stored-body cap, wipe-project (file, sidecars, Keychain key)

**M6 — Deep LLM detection + payload attacks**

- [ ] SSE reassembly, `tool_calls` parsing, input-field recording and usage counters; LLM endpoints listed on the AI tab
- [ ] Canary + regex payload sets run against a local DVAP lab; leaks recorded as findings with confidence levels
- [ ] OWASP coverage matrix renders (tested / partial / none) across LLM, Agentic and MCP lists

**M6.5 — Indirect injection + multi-turn**

- [ ] Local server serves pages with hidden instructions; a browsing/RAG agent that fetches them is caught
- [ ] Multi-turn runs inject at turn N against the Damn Vulnerable LLM Agent

**M7 — Scanner integration + MCP server**

- [ ] promptfoo and garak runs launched from the AI tab (pinned versions, garak in its own venv), results parsed into Findings
- [ ] Optional LLM judge produces probable-confidence findings, treating model output as untrusted
- [ ] OOB interaction server (self-hosted, scope-bound) catches blind injection and SSRF exfil
- [ ] MCP server (stdio, read-only): Claude Code can list exchanges, read one (secrets redacted), and add a finding

**M8 — Hardening**

- [ ] HTTP/2 (own framing + HPACK, or a library)
- [ ] MCP active tools (send_request, run_scan) with scope enforced in the engine and UI confirm
- [ ] mTLS client certs per host; session macros; remaining Intruder attack types
- [ ] Optional: Claude API assistant (off by default); signed `.app`

**M9 — Transparent capture (decided 2026-10-25)**

- [ ] Capture apps that ignore proxy settings: macOS Network Extension (or a `pf` redirect for a first version), opt-in with admin approval, and easy to turn off
- [ ] Captured flows get the same decrypt / bypass / pinning decisions and process attribution as proxied ones

**Later — Cyber Verification (not a build task)**

- [ ] Once the proxy is usable, get one resolved report on HackerOne or Bugcrowd (VDP programs count) or an accepted GitHub Security Advisory
- [ ] Then apply to Anthropic's Cyber Verification Program as an individual security researcher (Defense Access). Only needed if classifier blocks start slowing the payload-library work

## Portfolio and learning track

This is both a learning build and a portfolio piece for a possible pivot into security engineering. The milestone order already covers the fundamentals in sequence; this track adds what makes each one showable without skipping the understanding underneath.

End each milestone with three outputs:

- The working feature, demoable on its own.
- A short demo (GIF or clip) of it running against a lab target.
- A short write-up explaining the principle in your own words (for example, "how HTTP/1.1 message framing works and how smuggling abuses it" at M1, "why TLS interception needs a local root CA" at M3, "testing an LLM app for prompt injection" at M6). The write-up proves the understanding and it is what a hiring manager reads.

Use Burp and PortSwigger as references, not a separate track:

- Before building a feature, spend a few minutes with Burp's version to see what it shows and how it behaves. That is your informal spec.
- While building, run your proxy and Burp against the same traffic and diff the behaviour. A disagreement is a bug or a gap in understanding.
- When a concept is fuzzy, read the matching PortSwigger Academy topic instead of guessing.

Keep the repo public from day one, with CI, tests and a demo per milestone. M3 (working TLS interception) and M6 (LLM detection + attacks) are the two checkpoints worth showing even if the build pauses partway. The basic LLM flag at M2 gives an early taste of the differentiator. Reaching M6 matters more than polishing M4–M5.

## Test targets and scope

Active features (Repeater sends, Fuzzer, AI attacks, MCP `send_request`) only run against hosts in the project scope list. The default scope is `localhost`, `127.0.0.1`, and `*.test`.

| Target | For | Runs |
| --- | --- | --- |
| Local test origin | Protocol tests (M1–M3) | `internal/testorigin` |
| OWASP Juice Shop | Web testing practice | Docker, localhost |
| DVWA | Classic web vulns | Docker, localhost |
| PortSwigger Web Security Academy | Guided labs | Lab instances issued to you; add each lab host to scope |
| [DVAP](https://github.com/sonuoffsec/DVAP) | OWASP LLM Top 10 labs, local Ollama models | Docker, localhost |
| [Damn Vulnerable LLM Agent](https://github.com/WithSecureLabs/damn-vulnerable-llm-agent) | Prompt injection in a ReAct agent | Python, localhost |
| [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | Tool poisoning, rug pulls, indirect injection (10 challenges) | Docker, localhost |
| Lakera Gandalf | Prompt-injection practice | Browser only; don't point automated scans at it |

Review any lab repo before running it; these are intentionally vulnerable and run on your own machine. Passive capture of normal browsing is fine. Never run active features against sites you don't own or have written permission to test.

## Sources

- [ncruces/go-sqlite3](https://github.com/ncruces/go-sqlite3) and its [adiantum VFS](https://pkg.go.dev/github.com/ncruces/go-sqlite3/vfs/adiantum)
- [SQLCipher Go support thread (Zetetic)](https://discuss.zetetic.net/t/sqlcipher-is-supported-in-golang/5738)
- [Burp Suite DAST MCP server](https://portswigger.net/burp/documentation/dast/user-guide/using-ai/mcp-server)
- [OWASP Top 10 for LLM Applications 2026 (Cycode)](https://cycode.com/blog/owasp-top-10-llm-applications/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-application)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [promptfoo vs garak vs PyRIT (DEV)](https://dev.to/ventrova/how-to-test-your-llm-app-for-prompt-injection-promptfoo-vs-garak-vs-giskard-vs-pyrit-vs-2oim)
- [garak and PyRIT (8kSec)](https://8ksec.io/red-teaming-llm-applications-garak-pyrit/)
- [DVAP](https://github.com/sonuoffsec/DVAP)
- [Damn Vulnerable LLM Agent](https://github.com/WithSecureLabs/damn-vulnerable-llm-agent)
- [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
