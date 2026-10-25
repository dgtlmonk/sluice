# Sluice — Claude Code rules

Burp-style intercepting proxy. Go engine, Wails shell, React + TypeScript UI. Full spec: [SPEC.md](SPEC.md).

This is a learning project: explain non-obvious protocol and crypto code in comments, and prefer readable code over clever code.

## Workflow

- Work one milestone at a time (M0 first). Stop at the end of each and list the acceptance checks with how to verify them.
- Ask before adding a dependency (Go module or npm package) not listed in the SPEC.md tech stack.
- Pin UI and engine dependencies and scanner/tool versions; don't float majors.
- macOS is the only platform to implement now; other platforms return a stubbed "not supported" error.

## Protocol code

- Hand-write the HTTP/1.1 parser and TLS MITM on raw sockets. Do not use `net/http` in the proxy path; it hides the parsing being learned.
- Use `crypto/tls` `GetCertificate` / `NextProtos` for the intercept hooks.
- `net/http` and `httptest` may be used in tests as a reference oracle, including differential fuzzing. If the parser stalls past M3, this no-library rule breaks before the project does.
- Reject ambiguous HTTP framing (see SPEC.md, HTTP/1.1). Every rejection rule has a test.
- Every protocol feature gets an integration test against `internal/testorigin`. No tests hit the public internet.

## Architecture

- Engine packages never import UI code; the UI only consumes Wails bindings and events.
- All OS calls go through `internal/platform` (Keychain, cert trust, system proxy, browser launch).
- Functionality first. Optimization work (memory, speed) goes on the SPEC.md "Optimization backlog", not into milestones.
- Traffic forwarding never blocks on observers. The live event path is lossy and counts drops; the storage path is lossless and surfaces any failure as an error.

## Security

- Never bind the listener to anything but loopback by default.
- Never log or print the CA private key, the database key, auth headers, or cookies.
- The database key comes from the Keychain and is applied with `PRAGMA hexkey` right after open; never put it in a URI, file, log, or command-line argument.
- Redact secrets on every path that leaves the store: logs, exports, MCP output, anything sent to an LLM.
- Treat all captured traffic as untrusted input anywhere it feeds an LLM (judge or assistant).
- Enforce the scope list in the engine, not just the UI, for every active send, redirect hop and resolved IP.
