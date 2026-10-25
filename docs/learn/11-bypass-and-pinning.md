# 11 — Not decrypting: the bypass list, h2-only tunnels and pinning

## The idea

An intercepting proxy does not have to decrypt every CONNECT. It can also act as a plain TCP pipe: forward the client's TLS bytes to the origin untouched, so the client finishes its handshake with the *real* site. That is a **raw tunnel**. The proxy then sees only what is in cleartext: the CONNECT line, the **ClientHello** (SNI, ALPN, versions, ciphers) and how many bytes flow each way.

The choice has to be made *before* the proxy answers the handshake, because once it has sent its own certificate there is no going back. So the proxy reads the ClientHello first, without answering it, decides, and then replays those exact bytes either into its own TLS server (decrypt) or to the origin (tunnel).

```
CONNECT host:443  ->  200  ->  ClientHello (read, not answered)
                                  |
              bypass? h2-only? pinned? origin refuses http/1.1?
                 | yes                                 | no
     replay hello to origin, pipe bytes      replay hello to crypto/tls, mint leaf, decrypt
```

## Why it matters

- **Some clients cannot be decrypted without breaking them.** A gRPC client offers ALPN `h2` and nothing else; a proxy that only speaks HTTP/1.1 inside the tunnel would make it fail. Tunnelling raw keeps it working.
- **Some origins refuse HTTP/1.1.** If the origin answers the proxy's `http/1.1`-only offer with TLS alert 120 (`no_application_protocol`), decrypting would end in an error page. Better to step aside, and remember that host.
- **Certificate pinning.** Many mobile apps and some desktop tools accept only the site's real certificate (or its public key), not any certificate the OS trusts. They reject the minted leaf with a TLS alert right after seeing it. Retrying is pointless; tunnelling lets the app work while the tester knows why that host is opaque.
- **The same abort has a boring cause too.** A client that does not trust the root CA also aborts right after the certificate. Calling that "pinning" would send the tester chasing the wrong problem, so the pinning flag is only meaningful when the CA trust check passes.
- **Some traffic should never be decrypted.** Banking, health, OS update and Apple/Google account traffic is often out of scope and full of secrets; a bypass list keeps it out of the history entirely.

## What Sluice does

- **ClientHello reader** (`internal/engine/clienthello.go`): hand-written, strict bounds checks. It reassembles a hello split across records, rejects duplicate extensions, trailing bytes and bad lengths, and returns the exact bytes it read so they can be replayed. Every rejection rule has a test, and a fuzz target checks it never panics.
- **Decision order** (`internal/engine/mitm.go`, `tlspolicy.go`): bypass list or a learned flag (SNI or CONNECT host) -> tunnel; client ALPN is only `h2` -> tunnel; otherwise Sluice dials the origin offering only `http/1.1`. An alert 120, or an origin that picks another protocol, marks the host "refuses http/1.1" and tunnels. A successful probe connection is pooled and used by the first request.
- **Bypass patterns**: `host` matches exactly, `*.example.com` matches every subdomain but not `example.com` itself. Set in Settings, applied live, saved to `bypass.json` next to the project.
- **Pinning flag**: when the client answers the leaf with a fatal TLS alert that means "I refuse this certificate" — 42 `bad_certificate`, 43 `unsupported_certificate`, 44 `certificate_revoked`, 45 `certificate_expired`, 46 `certificate_unknown` or 48 `unknown_ca` — *and* the app's cached CA trust check says the root is trusted, the CONNECT row gets "pinning suspected" and the host is tunnelled from then on. 40 `handshake_failure`, 49 `access_denied` and 51 `decrypt_error` are left out: they do not single out the certificate. The engine never calls the OS: the app passes in a `CATrusted` function backed by `internal/platform` and cached for a minute. With an unknown or failed check, nothing is flagged. Learned flags live in memory only, so restarting Sluice clears them.
- **Unused connections**: a client that closes without an alert (FIN, `close_notify`, or a reset), before its ClientHello or right after seeing the leaf, is recorded as a muted row: "client closed connection unused (likely browser preconnect)". It is not an error and never sets the pinning flag. A timeout is still an error, never a pin.
- **Display**: every CONNECT row to port 443, or that sent a ClientHello, is shown as `https://host`. A row that never got a response shows `—` for its status; the reason is in the detail pane strip.
- **Tunnelled rows** are kept in history as one `CONNECT` row with the reason, the JA4 fingerprint (page 12) and byte counts each way. Learned hosts are listed in Settings, with "Add to bypass list" and "Forget".
- **Not yet**: learned flags and per-row TLS facts live in memory for the session (the store has no column for them yet); there is no scope check on CONNECT targets.

## Lesson: the preconnect false positive

The first version also treated a bare close (EOF) as "the client rejected the certificate". Browsing through Brave (Chromium) then flagged `star-randsrv.bsg.brave.com` as pinned, although later requests to the same host were decrypted fine. The cause: Chromium opens *speculative* connections (preconnect, socket-pool warm-up). Three CONNECTs went out in the same millisecond; one carried the request, the other two finished their part of the handshake and were then dropped silently once Chromium no longer needed them.

So a silent close says nothing about the certificate. A TLS client that actually refuses a certificate is required to say so with an alert (RFC 8446 §6.2; RFC 5246 §7.2.2), and browsers, OpenSSL, BoringSSL and Go all do. Only the alert is evidence. Over TCP, Go's `crypto/tls` reports a received alert as a `*net.OpError` with `Op == "remote error"` (`remote error: tls: unknown certificate authority`); `tls.AlertError` is only wrapped into errors on QUIC. Sluice checks both shapes (`receivedAlert` in `mitm.go`).

The rule for any detector: count the signal that *means* the thing, not one that merely often comes with it. False positives here are costly: the host stops being decrypted.

## Further reading

- [mitmproxy — Ignoring domains](https://docs.mitmproxy.org/stable/howto-ignoredomains/) — the same feature in mitmproxy, and why ClientHello peeking is needed.
- [PortSwigger — Burp TLS settings](https://portswigger.net/burp/documentation/desktop/settings/network/tls) — Burp's TLS pass-through list.
- [OWASP — Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning) — what pinning is and why apps do it.
- [Android — Network security configuration](https://developer.android.com/privacy-and-security/security-config) — how Android apps pin, and why user-added CAs are ignored by default.
- [RFC 8446 §6.2 — TLS 1.3 error alerts](https://www.rfc-editor.org/rfc/rfc8446#section-6.2) — what each certificate alert means.
- [RFC 7301 §3.2 — ALPN](https://www.rfc-editor.org/rfc/rfc7301) — the `no_application_protocol` alert.
- [RFC 8446 §4.1.2 — ClientHello](https://www.rfc-editor.org/rfc/rfc8446) — the message the reader parses.
- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/) — a real ClientHello, byte by byte.
