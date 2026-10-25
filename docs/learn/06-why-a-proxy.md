# 06 — Why a proxy: seeing traffic versus changing it

## The idea

A **forward proxy** is a program the client sends its requests to instead of the real server. The client still says where it wants to go; the proxy opens the connection to that destination, passes the request on, and passes the response back. Every byte crosses the proxy, in both directions.

`curl -x` makes this visible. It takes two addresses, and they mean different things:

```
curl -x http://127.0.0.1:8080 http://example.test/search?q=go
        └─ proxy address ───┘ └─ real destination ──────────┘
```

- `-x` (long form `--proxy`) is **where curl connects**: Sluice, on loopback port 8080.
- The URL is **where the request is meant to go**. curl writes it in full in the request line (`GET http://example.test/search?q=go HTTP/1.1`), so the proxy knows the destination (see [03](03-forwarding-proxy.md)).

Drop `-x` and curl connects straight to `example.test`. The request never touches Sluice, and Sluice sees nothing. A proxy only sees traffic that a client was told to send to it.

There are three common ways to look at HTTP traffic, and they differ in what they can do:

| Tool | Sees | Can change | Scope |
|------|------|------------|-------|
| Browser DevTools (Network tab) | requests and responses, decrypted | no (beyond "resend") | one browser, one tab's view |
| Packet capture (Wireshark, tcpdump) | every packet on an interface | no | everything on the wire, but HTTPS is ciphertext |
| Intercepting proxy (Sluice, Burp) | every request and response sent through it | **yes** | only clients pointed at it |

**Interception** means three things: **stop** a request before it leaves, **edit** it (or the response), and **replay** it later, changed or not. That is only possible for whoever forwards the bytes. DevTools and Wireshark watch a copy; the real bytes have already gone. A proxy holds the real bytes, so it decides what is sent.

## Why it matters

- **Watching is not testing.** Most security testing is "what happens if this value is different?": a changed id, a removed header, a doubled parameter. That needs a tool on the path, not beside it.
- **The client must be pointed at the proxy**, and each client is pointed differently:
  - a per-tool flag or variable: `curl -x`, `HTTP_PROXY` / `HTTPS_PROXY` for many command-line tools;
  - a browser setting: Firefox has its own proxy settings; Chrome and Safari use the system's;
  - the **OS system proxy** (macOS: System Settings, Network, Proxies), which most apps that use the system networking stack follow.
- **The localhost gotcha.** Chrome and Safari never send requests for `localhost` or `127.0.0.1` through a proxy: loopback is bypassed implicitly, whatever the settings say. Testing a local app through Sluice from those browsers silently goes direct. Firefox does the same by default, but it can be told not to: set `network.proxy.allow_hijacking_localhost` to `true` in `about:config`. Or give the local app a name other than `localhost`.
- **A missing proxy looks like nothing.** If the client is not pointed at the proxy, there is no error: the app just works and the history stays empty. An empty grid usually means "the client went direct", not "the proxy is broken".
- **HTTPS changes the picture.** For `https://` URLs the client asks the proxy for a tunnel (`CONNECT example.test:443`) and then speaks TLS through it. The proxy forwards ciphertext, exactly like Wireshark sees ciphertext. To read and change it, the proxy must **terminate TLS** itself: present a certificate for `example.test` signed by its own CA, which the client must trust. That is M3.

## What Sluice does

- Sluice is an intercepting forward proxy. It listens on loopback only (`127.0.0.1:8080` by default; `SLUICE_PROXY_ADDR` picks another loopback address) and refuses any non-loopback address, so nothing else on the network can use it.
- In M1 and M2 it forwards plain HTTP/1.1 and records every exchange: the History grid shows it live, and the store keeps the raw request and response (see [05](05-storage-path.md)). Stop, edit and replay are built on top of this in later milestones.
- Clients are pointed at it by hand for now: `curl -x http://127.0.0.1:8080 …`, or a browser's proxy settings. Setting the macOS system proxy and launching a pre-configured browser go through `internal/platform` in a later milestone.
- HTTPS interception (a local CA in the Keychain, a certificate per host minted on demand) arrives in M3. Until then a `CONNECT` request is answered with `405`, so an `https://` URL is not proxied.

## Further reading

- [MDN — Proxy servers and tunneling](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling) — forward and reverse proxies, and `CONNECT` tunnels for HTTPS.
- [curl man page — `-x, --proxy`](https://curl.se/docs/manpage.html#-x) — the proxy flag, its URL forms and the proxy environment variables.
- [Everything curl — Proxies](https://everything.curl.dev/usingcurl/proxies/) — a gentler walk through curl and proxies.
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/) — packet capture: what it can see, and how.
- [Wireshark wiki — TLS](https://wiki.wireshark.org/TLS) — why HTTPS shows up as ciphertext, and what it takes to decrypt it.
- [PortSwigger — Burp Proxy](https://portswigger.net/burp/documentation/desktop/tools/proxy) — the intercepting proxy Sluice is modelled on.
- [Mozilla Support — Connection settings in Firefox](https://support.mozilla.org/en-US/kb/connection-settings-firefox) — pointing Firefox at a proxy.
- [Chromium — Proxy support in Chrome](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md) — including the implicit bypass rules for localhost.
