# 05 — The storage path: lossless history, encrypted at rest

## The idea

Every exchange Sluice forwards leaves on two paths at once:

- The **live path** feeds the History grid. It is **lossy**: a bounded queue that drops events when the UI cannot keep up, and counts every drop. Losing a live event costs nothing, because the row is still in the store and the grid can read it again.
- The **storage path** feeds the project database. It is **lossless**: history must not silently lose a row. If a row cannot be saved, the user is told.

The hard rule over both: **forwarding never waits for an observer.** A browser must not stall because the UI is busy or the disk is slow.

A bounded channel cannot give "never block" and "never lose" at the same time. When it is full, the sender must either wait (blocks forwarding) or drop (loses a row). The way out is to move the limit from **row count** to **memory**, and to make the one remaining failure loud:

```
connection goroutine                      storage writer (one goroutine)
  exchange done ─► Enqueue ─► [ queue: slice + mutex, byte budget ] ─► batch of 256 ─► BEGIN … COMMIT
                     │ never waits for disk                                  │ retry with backoff
                     └─ over budget? refuse, count "unsaved", raise error     └─ still failing? count "failed", raise error
```

The project database is one **SQLite** file. SQLite does not read or write the disk itself; it goes through a **VFS** (virtual file system) layer. The **Adiantum** VFS sits between SQLite and the OS and encrypts every 4 KiB block on the way out and decrypts it on the way in: the main file, the WAL (write-ahead log) and the journal. SQLite only ever sees plaintext pages, so indexes, WAL and transactions work as usual.

[Adiantum](https://eprint.iacr.org/2018/720) is a **length-preserving** cipher built by Google for low-end devices without AES hardware. Length-preserving means a 4 KiB block stays 4 KiB, which is exactly what a page-based database needs: no room is required for a nonce or a tag.

## Why it matters

- **Captured traffic is a pile of secrets.** A proxy history holds session cookies, `Authorization: Bearer` tokens, API keys, passwords in login forms, and personal data in responses. Anyone who copies the history file can replay those sessions. Burp project files are a known target for exactly this reason.
- **Laptops get lost and backed up.** A plaintext `.sluice` file would end up in Time Machine, cloud sync and support bundles. Encrypting at rest means a copied file is useless without the key.
- **The key must live somewhere else.** A key in a config file next to the database protects nothing. The macOS **Keychain** keeps it in the user's login keychain, which is itself encrypted with the user's login password.
- **Keys leak through side doors.** A key in a URI parameter (`?hexkey=…`) is readable by other code holding the connection and ends up in logs and error messages. A key on a command line is visible to every local user via `ps`.
- **Silent loss destroys trust in a security tool.** If history quietly drops rows under load, a tester cannot tell "the app never sent that request" from "the proxy forgot it". Counting every lost row turns a mystery into a visible bug.
- **Batching is what makes one writer fast enough.** Each SQLite commit appends to the WAL and (by default) waits for an `fsync`. Committing 256 rows in one transaction costs about the same as committing one.

What Adiantum does **not** do: it has no authentication tag, so it does not detect tampering, and it is deterministic, so someone who sees several snapshots of the file can tell which blocks changed. The threat model is a copied or stolen file, not an attacker who can already write to your disk.

## What Sluice does

Storage path:

- The engine exposes three hooks: `HeadTap` (each head exactly as received), `BodyTap` (raw body bytes as they stream, chunk framing included) and `Done` (once per exchange, after the taps). All three run inline and only copy bytes.
- A capture buffer assembles head + body per in-flight exchange. Each stored body is capped at 32 MB and flagged `body_truncated` past that; forwarding is never truncated.
- `Done` appends the finished exchange to the storage queue. The queue is bounded by bytes (512 MiB), not rows, so a slow disk only makes rows wait in memory.
- A single writer goroutine drains the queue in batches of up to 256 rows, one transaction per batch. A batch transaction is all-or-nothing.
- A failed batch is retried three times with exponential backoff (50, 100, 200 ms; the wait is cut short if the writer is stopped). If it still fails, the writer retries it **row by row**, one transaction each, so one poison row (say, a duplicate id) costs only itself: the good rows are saved, and only the rows the database still refuses are counted as **failed** and reported with their id. Nothing is retried forever, because one bad batch would otherwise stall the whole queue.
- If the byte budget is ever exhausted, the row is refused, counted as **unsaved**, and a "history incomplete" error is raised. That state is a bug to fix, not normal operation.
- Past 4096 waiting rows the writer counts as **behind**: an early warning, with nothing lost yet.
- Failures reach the UI as a `storage:error` event and as counters in the status bar (`Saved`, `History incomplete: N not saved`, `Store behind`). The invariant the tests check is `enqueued = saved + failed + abandoned + queued`.
- Shutdown stops the proxy first, then drains the queue (up to 10 s) before closing the database. If the drain times out, the writer is stopped first: the insert in flight is cancelled and awaited, so the database is never closed under a running insert. Rows still queued are counted as **abandoned** (part of `unsaved`) and reported. Errors raised during the drain, when the UI is already gone, are written to the log (ids and reasons only, never headers or bodies).
- If the project cannot be opened, or its largest stored id cannot be read (new ids would collide with stored rows), the store is treated as unavailable: the proxy keeps forwarding, every exchange is counted as not saved with the reason, a `storage:error` event is raised, and the status bar shows `storage off: <reason>`.
- On launch the grid loads the newest 10,000 stored rows (metadata only; bodies stay in the database until a row is selected).

Encryption at rest:

- One file per project (default `~/Library/Application Support/Sluice/default.sluice`), mode `0600`, with `-wal`/`-shm` tightened to `0600` too.
- The 32-byte key is random (`crypto/rand`), created with the project and stored in the login Keychain, one item per project file.
- The key is applied with `PRAGMA hexkey` on every new connection, before anything reads the file. It never appears in the URI, a file, a log or a command line, and errors from that PRAGMA are reduced to their result code so the statement text (which holds the key) cannot leak.
- Temp files are kept in memory (`PRAGMA temp_store = memory`), so sorts and temp tables never write plaintext rows to disk.
- Secrets are stored as captured, inside the encrypted file, so replay works after a restart. The detail pane shows them unredacted, because it is the user's own view of their own store.
- **Rule for future paths (not implemented yet):** exports, MCP output and anything sent to an LLM do not exist in M2. When each one is built, it must redact (`Authorization`, `Cookie`, `Set-Cookie`, API-key-shaped values) before data leaves the store. Today the only path out is the log, and the storage code never logs headers, bodies or the key.

## Further reading

- [SQLite — Write-Ahead Logging](https://www.sqlite.org/wal.html) — how WAL works and why commits are cheap appends.
- [SQLite — The Virtual File System](https://www.sqlite.org/vfs.html) — the layer the encryption plugs into.
- [SQLite — Atomic Commit](https://www.sqlite.org/atomiccommit.html) — why one transaction per batch is all-or-nothing.
- [ncruces/go-sqlite3 — adiantum VFS](https://pkg.go.dev/github.com/ncruces/go-sqlite3/vfs/adiantum) — the VFS Sluice uses, and `PRAGMA hexkey`.
- [Crowley and Biggers — Adiantum: length-preserving encryption for entry-level processors](https://eprint.iacr.org/2018/720) — the cipher's design paper.
- [Google Security Blog — Introducing Adiantum](https://security.googleblog.com/2019/02/introducing-adiantum-encryption-for.html) — the motivation in plain words.
- [Apple — Keychain services](https://developer.apple.com/documentation/security/keychain-services) — where the database key lives.
- [OWASP Top 10 for LLM Applications — Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) — why captured traffic must be redacted before it reaches an LLM.
- [Go — sync.Mutex](https://pkg.go.dev/sync#Mutex) and [Go blog — Go Concurrency Patterns: Pipelines](https://go.dev/blog/pipelines) — the producer/consumer shape behind the queue.
