# 03 — The forwarding proxy

## The idea

A **forward proxy** sits between a client and every server it talks to. The browser is told "send everything to 127.0.0.1:8080". It then writes the full URL in the request line, so the proxy knows where to go:

```
GET http://example.test/search?q=go HTTP/1.1\r\n      <- absolute-form (client -> proxy)
GET /search?q=go HTTP/1.1\r\n                         <- origin-form   (proxy -> origin)
Host: example.test\r\n
```

The first form is **absolute-form**. The second is **origin-form**, what a server normally sees. The proxy reads one, opens a connection to `example.test`, and sends the other.

So a request crosses two connections, or **legs**: client to proxy, and proxy to origin. Each leg is its own TCP connection with its own rules. Headers fall into two groups:

- **End-to-end** headers describe the message (`Content-Type`, `Cookie`). They pass through.
- **Hop-by-hop** headers describe one connection (`Connection`, `Keep-Alive`, `TE`, `Upgrade`). The proxy consumes them and does not forward them. `Connection` can also name extra headers to strip on this hop.

Both legs reuse connections. **Keep-alive** sends many requests over one TCP connection. A **connection pool** keeps idle upstream connections open so the next request to the same host skips the TCP handshake.

## Why it matters

- Every later feature (history, intercept, replay, HTTPS) sits on top of this forwarding loop. If it mishandles a byte, every tool above it lies.
- `Connection` naming a header is a smuggling trick. `Connection: Content-Length` asks the proxy to strip `Content-Length`. A proxy that used that header to frame the body, then obeys and strips it, forwards a body with no length. The origin reads the body as the next request.
- A reused connection must be **clean**. On an idle keep-alive connection the origin has no right to send anything. If stray bytes are waiting there, the next request would read them as the start of its response. That is a **response desync**: one user can get another's response.
- The two legs may disagree on framing. A chunked response cannot go to an HTTP/1.0 client, because 1.0 has no chunked coding. The proxy must decode the body and **re-frame** it for each leg.
- **Streaming, not buffering.** Server-sent events and LLM token streams send a few bytes at a time for minutes. A proxy that waits for the whole body breaks them. It also uses memory for every large download.
- **Timeouts** stop a peer from holding a connection forever. A **slowloris** attack opens many connections and sends a request head one byte at a time, never finishing. A timeout that resets on every read never fires.
- **`Expect: 100-continue`** lets a client ask "may I send this large body?" before sending it. A proxy that handles it badly deadlocks: the client waits for `100`, the server waits for the body.
- **Retries** are tempting when a pooled connection turns out to be dead. But the origin may already have acted on the request. Repeating a `POST` could pay twice. Only **idempotent** methods (`GET`, `PUT`, `DELETE`, ...) have the same effect when sent twice.
- **Loopback only.** A proxy on `0.0.0.0` accepts anyone on the network. That is an **open relay**: strangers send their traffic through your machine and your IP. Worse, they can reach hosts on your private network.

## What Sluice does

Request handling:

- Requires absolute-form for plain HTTP. Rebuilds the request in origin-form and always speaks HTTP/1.1 upstream.
- Ignores the client's `Host` and sets it from the URL (RFC 9112 §3.2.2). Otherwise `http://a/` with `Host: b` could be routed to `a` but read as `b`.
- Refuses `CONNECT` with `405` for now. HTTPS interception arrives in M3.
- Strips hop-by-hop headers: `Connection`, `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authorization`, `Proxy-Authenticate`, plus anything `Connection` names. Order and case of the rest are kept.
- Rejects a `Connection` header that names `Content-Length`, `Transfer-Encoding` or `Host` with `400`.

Connections:

- Keeps both legs alive (RFC 9112 §9.3): HTTP/1.1 unless `close` is listed, HTTP/1.0 only if `keep-alive` is listed.
- Pools idle upstream connections, at most 8 per host, idle at most 90 s. The key includes http vs https, so they can never be swapped.
- Before reusing a pooled connection, checks it is **quiet**: a 1-byte read with a 1 ms deadline. A timeout means healthy. Data or EOF means the conn is dropped.
- A pooled conn can still die between check and use. Then Sluice retries once on a fresh conn, but only for idempotent methods and only if no request body was read. `POST`, `PATCH` and `CONNECT` are never retried.

Bodies:

- Decodes the origin's framing and re-encodes it for the client:

  | origin framing   | client 1.1                 | client 1.0                    |
  |------------------|----------------------------|-------------------------------|
  | none / Content-Length | as-is                 | as-is                         |
  | chunked          | re-chunked                 | close-delimited, then close   |
  | close-delimited  | chunked (conn kept alive)  | close-delimited, then close   |

- Streams every body and flushes each piece at once, so SSE and token streams arrive as they are produced.
- If the origin fails mid-body, headers are already sent, so no error status is possible. Sluice closes the client connection without the final chunk; the client sees the body is incomplete.
- Forwards 1xx responses (`100`, `103 Early Hints`). Answers `Expect: 100-continue` itself and strips `Expect` upstream. Cost: the origin can no longer refuse an upload before it is sent.

Timeouts (defaults):

- Dial 10 s. Response head 60 s. Idle on either leg 90 s.
- Idle timeouts renew on every read and write, so a live stream lives as long as it keeps moving.
- A request head has an absolute cap of 30 s from its first byte, however slowly it trickles. This is the slowloris defence.
- Origin unreachable or broken before any response byte: `502`. Timed out: `504`.

Listener:

- Binds `127.0.0.1:8080` by default. An empty host (`:8080`) is refused. `localhost` is pinned to `127.0.0.1` rather than resolved, since `/etc/hosts` could point it anywhere. Wider binds need an explicit opt-in.

## Further reading

- [RFC 9112 §3.2 — Request Target](https://www.rfc-editor.org/rfc/rfc9112#section-3.2) — origin-form, absolute-form, and the proxy `Host` rule.
- [RFC 9112 §9 — Connection Management](https://www.rfc-editor.org/rfc/rfc9112#section-9) — persistence, keep-alive, and closing.
- [RFC 9110 §7.6.1 — Connection](https://www.rfc-editor.org/rfc/rfc9110#section-7.6.1) — hop-by-hop fields and what a proxy must strip.
- [RFC 9110 §9.2.2 — Idempotent Methods](https://www.rfc-editor.org/rfc/rfc9110#section-9.2.2) — which requests are safe to retry.
- [RFC 9110 §10.1.1 — Expect](https://www.rfc-editor.org/rfc/rfc9110#section-10.1.1) — the `100-continue` handshake.
- [MDN — Connection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection) — header reference.
- [MDN — Keep-Alive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive) — header reference.
- [MDN — Proxy servers and tunneling](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling) — forward vs reverse proxies.
- [Cloudflare — Slowloris DDoS attack](https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/) — how the attack works.
- [PortSwigger Web Security Academy — HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) — includes desync via connection reuse.
