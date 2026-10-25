# 02 — Request smuggling and strict framing

## The idea

A message body can announce its length two ways:

- `Content-Length: 11` — the body is exactly 11 bytes.
- `Transfer-Encoding: chunked` — the body arrives in pieces, each prefixed by its size in hex; a zero-size piece ends it.

```
4\r\n
Wiki\r\n
0\r\n
\r\n
```

**Request smuggling** happens when two servers in a chain (a proxy and the origin behind it) pick different lengths for the same bytes. The front server thinks the request ended; the back server keeps reading. The leftover bytes become a second, hidden request — one the front server never checked. Attackers use it to bypass access rules, poison caches, or steal other users' requests.

The classic case: send both headers. One server trusts `Content-Length`, the other trusts `Transfer-Encoding`.

## Why it matters

- Sluice sits in exactly the position where smuggling happens: between client and origin.
- A lenient parser would make Sluice itself a smuggling gap.
- Later, Sluice is the tool you use to probe *other* servers for these gaps, so you need to know the rules cold.

The one rule behind every check below: **if two honest parsers could read a message two ways, reject it. Never pick.**

## What Sluice does

Body length is decided in this order (RFC 9112 §6.3, made stricter by SPEC.md):

1. Both `Content-Length` and `Transfer-Encoding` present → reject.
2. `Transfer-Encoding` whose last coding is `chunked` → read as chunked.
3. `Transfer-Encoding` whose last coding is not `chunked` (`gzip`, `chunked, gzip`) → reject. `chunked` appearing twice → reject.
4. `Content-Length` only → every value must be digits and all values must match (`5, 5` is fine, `5, 50` is rejected).
5. Neither header → a request has no body; a response is read until the server closes the connection.

Extra checks, each a known smuggling trick:

- Empty list items such as `Content-Length: 5,` or `Transfer-Encoding: ,chunked` → reject. Some servers skip the empty item, some fail; that disagreement is the gap.
- `Transfer-Encoding` on an HTTP/1.0 request → reject. HTTP/1.0 has no chunked coding.
- Trailers (headers after a chunked body) may not set `Content-Length`, `Transfer-Encoding` or `Host`.
- Chunk sizes are checked for overflow, and every chunk must end in CRLF.

Every rejection rule has its own test. A differential fuzz test (feeding the same random bytes to Sluice and to Go's `net/http`) is planned to catch disagreements nobody thought of.

## Further reading

- [RFC 9112 §6.3 — Message Body Length](https://www.rfc-editor.org/rfc/rfc9112#section-6.3) — the official order of rules Sluice follows (and tightens).
- [RFC 9112 §7.1 — Chunked Transfer Coding](https://www.rfc-editor.org/rfc/rfc9112#section-7.1) — exact chunk syntax, extensions and trailers.
- [PortSwigger Web Security Academy — HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) — free explanations plus hands-on labs.
- [James Kettle — HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) — the 2019 research that brought smuggling back into focus.
- [MDN — Transfer-Encoding](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding) — header reference.
