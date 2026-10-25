# 01 — The HTTP/1.1 parser

## The idea

HTTP/1.1 is text over a TCP connection. A message is a **head** (start line plus header lines, each ending in CRLF, then one empty line) followed by an optional **body**.

```
POST /login HTTP/1.1\r\n
Host: example.test\r\n
Content-Length: 11\r\n
\r\n
user=alice
```

The parser turns that byte stream into messages. Its hardest job is not reading headers. It is knowing **where one message ends and the next begins**, because one connection carries many messages back to back (keep-alive).

## Why it matters

- A proxy sees every byte between client and server. Before it can show, edit, or replay a request, it must split the stream into messages correctly.
- Every later feature — history, intercept, replay, the HTTPS layer, the LLM judge — builds on these messages.
- Security tools show what was actually on the wire. Sluice keeps the raw head bytes, so you see odd spacing, casing, or duplicate headers that a library would quietly normalise.
- That is why the parser is hand-written and `net/http` is banned from the proxy path: the library hides exactly the rules this project exists to learn. `net/http` is still used in tests, as a reference to compare against.

## What Sluice does

- Reads the head line by line and requires CRLF. A bare CR or bare LF is rejected.
- Rejects obsolete line folding (a header continued on an indented next line).
- Rejects whitespace between a header name and its colon.
- Requires exactly one `Host` on HTTP/1.1 requests.
- Enforces limits so a hostile peer cannot exhaust memory: 8 KiB request line, 100 headers, 64 KiB head. Over-limit headers get `431 Request Header Fields Too Large`; malformed input gets `400`.
- Streams bodies instead of loading them into memory, so large uploads and server-sent events flow through as they arrive.
- Knows which responses never have a body regardless of headers: replies to `HEAD`, `1xx`, `204`, `304`, and `2xx` to `CONNECT`.

How the body length is chosen is the subject of [02 — Request smuggling](02-request-smuggling.md).

## Further reading

- [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112) — the message syntax this parser implements. Start with §2 (message format) and §5 (field syntax).
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) — what methods, status codes and headers mean, independent of HTTP version.
- [MDN — HTTP messages](https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages) — friendly overview with diagrams.
- [RFC 6585 §5 — 431 Request Header Fields Too Large](https://www.rfc-editor.org/rfc/rfc6585#section-5) — the status code used for header limits.
