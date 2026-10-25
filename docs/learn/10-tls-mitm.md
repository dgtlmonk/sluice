# 10 — TLS interception: CONNECT, the handshake, SNI and ALPN

## The idea

For plain HTTP a browser sends the proxy the whole URL (`GET http://site/path`). For HTTPS it cannot: the request is encrypted end to end. Instead it asks the proxy for a raw pipe with **CONNECT**:

```
CONNECT example.com:443 HTTP/1.1      browser -> proxy
HTTP/1.1 200 Connection Established   proxy -> browser
<TLS bytes from here on>
```

After the `200`, the browser runs a **TLS handshake** as if the proxy were the site. In TLS 1.3 that is one round trip:

1. **ClientHello** (cleartext): supported versions and ciphers, a key share, and two extensions that matter here:
   - **SNI** (Server Name Indication): the host name the client wants. It must be cleartext because the server picks its certificate before any key exists.
   - **ALPN** (Application-Layer Protocol Negotiation): the protocols the client speaks after the handshake, for example `h2, http/1.1`. The server picks one.
2. **ServerHello** + certificate + a signature proving the server holds that certificate's private key. Everything after ServerHello is encrypted.
3. The client checks the certificate chain against its trust store and the name against SNI, then both sides switch to application data.

A **MITM proxy** answers that handshake itself. It reads the SNI, mints a certificate for that name signed by its own root CA (page 09), and finishes the handshake. Then it opens a *second*, ordinary TLS connection to the real site, where it is the client and checks the real certificate. Between the two it sees plaintext HTTP.

```
browser ==TLS (Sluice leaf)==> Sluice ==TLS (real cert, verified)==> example.com
```

## Why it matters

- **Most traffic worth testing is HTTPS.** Without interception a proxy sees only "CONNECT example.com:443" and an opaque byte stream.
- **ALPN decides what you have to parse.** Browsers prefer HTTP/2. If the proxy offered `h2` it would have to speak binary framing; by offering only `http/1.1` it makes the browser fall back to the text protocol.
- **SNI and the CONNECT host can differ.** The client chooses both. The proxy must validate whatever name it is about to sign; a careless one would sign anything the client asks for.
- **The proxy must not weaken the upstream check.** The browser can no longer see the real certificate, so if the proxy accepts a bad one silently, a real attacker between proxy and site goes unnoticed. The proxy has to verify it as strictly as a browser.
- **Handshake failures are signals.** A client that aborts right after receiving the minted certificate either does not trust the root or pins the real certificate.

## What Sluice does

- **CONNECT** (`internal/engine/mitm.go`): the target must be `host:port` (authority-form, port required). The host must be an IP literal or a plain DNS name, no wildcards, before anything is signed. A CONNECT with a body is refused. Without a loaded root CA the answer is `501`.
- **Client leg**: `crypto/tls` server with `GetCertificate`: the leaf is minted for the SNI name, or for the CONNECT host when there is no SNI (IP targets). Leaves are cached per host and all share one key, so signing is the only per-host cost. `NextProtos = ["http/1.1"]` forces HTTP/1.1. The handshake has the same absolute deadline as a request head.
- **Inside the tunnel** the same hand-written HTTP/1.1 loop runs over the decrypted stream. Requests must be origin-form (`/path`); they all go to the CONNECT target, and the exchange is stored with scheme `https`. The CONNECT itself is not a history row unless it failed.
- **Origin leg**: a TLS client offering only `http/1.1`, SNI = the client's SNI, certificate verified against the **system roots** (tests inject the test origin's own CA). A bad certificate becomes a `502` inside the tunnel, never a silent accept.
- **Pooling**: upstream connections are keyed by address, TLS and server name, so a TLS connection checked for one name is never reused for another, and never for plain HTTP.
- **Not yet**: bypass list, raw tunnelling for h2-only clients or hosts, pinning detection, and a scope check on CONNECT targets (there is no scope list in the engine yet).

## Further reading

- [RFC 9110 §9.3.6 — CONNECT](https://www.rfc-editor.org/rfc/rfc9110) — the method and its authority-form target.
- [MDN — CONNECT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/CONNECT) — a short introduction with examples.
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) — the handshake, message by message.
- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/) — every byte of a real handshake, explained.
- [RFC 6066 §3 — Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066) — the SNI extension.
- [Wikipedia — Server Name Indication](https://en.wikipedia.org/wiki/Server_Name_Indication) — history, and why SNI leaks the host (and what ECH changes).
- [RFC 7301 — ALPN](https://www.rfc-editor.org/rfc/rfc7301) — how client and server agree on `h2` or `http/1.1`.
- [Wikipedia — Application-Layer Protocol Negotiation](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation) — overview.
- [mitmproxy — How mitmproxy works](https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/) — explicit HTTPS proxying step by step, including the SNI problem.
- [Go — crypto/tls](https://pkg.go.dev/crypto/tls) — `GetCertificate`, `NextProtos`, `HandshakeContext`.
- [PortSwigger — Invisible proxying](https://portswigger.net/burp/documentation/desktop/tools/proxy/invisible) — how Burp handles clients that do not send CONNECT.
