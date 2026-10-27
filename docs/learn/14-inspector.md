# 14 — The Inspector: parameters, cookie flags and duplicates

## The idea

The Raw tab shows a request as bytes ([07](07-raw-vs-parsed.md)). Testing needs the next step: *which inputs does this request carry?* Query parameters, body parameters, cookies and headers are the places an attacker can put a payload. The **Inspector** (Burp has the same panel) lists them as name/value rows, one collapsible section each, decoded, with the raw form one toggle away.

It also checks the cookies the server sets, because a missing cookie flag is one of the most common findings in any web test.

## Why it matters

- **Every row is an input to fuzz.** Access-control and injection bugs live in parameters: `id=123` in a query, `"role":"user"` in a JSON body, `session=` in a cookie. A list makes it hard to miss one.
- **Duplicates are a finding, not noise.** `?id=1&id=2` is **HTTP parameter pollution**: PHP takes the last value, ASP.NET joins them with a comma, many Node and Python frameworks take the first or return a list. If a WAF or front end checks one copy and the back end uses the other, the check is bypassed. JSON has the same trap: `{"role":"user","role":"admin"}` is valid JSON, and parsers disagree on which key wins. `JSON.parse` keeps the last and hides the first, so the Inspector scans the body itself to keep both.
- **Decoding can reveal hidden bytes.** `%0d%0a` decodes to CR LF (header injection, log forging), `%00` to NUL (truncation), `%E2%80%AE` to a right-to-left override, `%EF%BB%BF` to an invisible byte-order mark. Decoded values are escaped again (`\x0d\x0a`, `\u{feff}`), so they show up instead of quietly breaking the layout. Bytes that are not valid UTF-8 (`%C0%AE`, an overlong `.` used to sneak past path filters) are shown as `\xc0\xae`; the valid text around them still decodes.
- **Cookie flags decide who can steal a session.**
  - `Secure`: without it the browser also sends the cookie over plain HTTP, readable by anyone on the network.
  - `HttpOnly`: without it page JavaScript can read the cookie through `document.cookie`, so one XSS bug steals the session.
  - `SameSite`: `Strict` or `Lax` keep the cookie off most cross-site requests, which blocks classic CSRF. With no `SameSite`, Chrome defaults to `Lax`, but other browsers and older versions may not. `SameSite=None` must come with `Secure`, or browsers drop the cookie.
  - `Domain`: shares the cookie with every subdomain, so a takeover of `forgotten.example.com` can read or overwrite it.
  - Prefixes: a `__Host-` cookie must be `Secure`, `Path=/` and have no `Domain`. `__Secure-` must be `Secure`. Browsers enforce this, which stops a subdomain or plain-HTTP page from planting the cookie.

Rule: a missing flag is a prompt to look, not a verdict. Why: a cookie the page's own JavaScript must read cannot be `HttpOnly`, and a deletion (`Max-Age=0`) needs no flags, so the Inspector marks deletions instead of flagging them.

## What Sluice does

- **Inspector button** in the detail pane opens a side panel. Its width and which sections are open are remembered per viewer.
- **Request attributes**: protocol, method, scheme, host, decoded path. A `#fragment` or a space in the request target is flagged: clients never send either, and servers split them differently.
- **Protocol** (the HTTP/1 | HTTP/2 pill): for decrypted traffic it comes from the request line, and it is always HTTP/1 for now, because Sluice answers ALPN with `http/1.1` only (real HTTP/2 is M8). When the client's JA4 fingerprint ([12](12-ja4-fingerprint.md)) shows it offered `h2` first, the row says **downgraded from h2**: bugs that exist only over HTTP/2, such as h2 request smuggling, cannot show up in this capture. A tunnel passed through raw because it was HTTP/2-only ([11](11-bypass-and-pinning.md)) lights HTTP/2; its request line is only the HTTP/1.1 `CONNECT`.
- **Sections**: query parameters, body parameters (`application/x-www-form-urlencoded`, JSON top-level keys, `multipart/form-data` field names and file names), request cookies, request headers, response headers, response cookies. Each has a count badge.
- **Rows** keep wire order and duplicates; a repeated name gets a `×2` badge. The badge is a warning where a repeat is a finding (parameters, request cookies, `Host`, `Content-Length`, `Transfer-Encoding`, auth headers; in responses `Content-Length`, `Location`, CORS and HSTS headers) and neutral where it is normal (`Set-Cookie`, `Vary`, `Accept`). `Host` and `Host ` (space before the colon) count as the same header, and the space is flagged: that is a request-smuggling tell. Long values are cut to one line; the `+` button (or a click on the value) expands them. Sections with more than 500 rows show them 500 at a time. "Raw values" switches every name and value to the captured form; hovering a value shows the other form.
- **Body parameters** also cover the CSRF trick: a JSON or form body sent as `text/plain` (or with no `Content-Type`) is parsed anyway and noted, because many servers ignore the type and `text/plain` needs no CORS preflight. Multipart parts are split only on whole delimiter lines, quoted `;` and `name=` stay inside their value, and a part that names its field twice or uses `filename*` (forbidden by RFC 7578, honoured by some servers) is flagged: those are the shapes that make a WAF and an app read different fields or file names.
- **Response cookies** show each `Set-Cookie` attribute and flag missing `Secure`, `HttpOnly` or `SameSite`, `SameSite=None` without `Secure`, broken `__Host-`/`__Secure-` rules (prefixes matched in any case, as RFC 6265bis does), and any `Domain`. Over plain HTTP the finding is the transport itself ("set over HTTP"); an `http://` origin cannot set `Secure` at all, and a `Secure` cookie from one is flagged as likely dropped.
- **Not parsed, with a note why**: binary bodies, chunked bodies (stored with their chunk framing), compressed bodies, and bodies cut short in view (rows come from the first part only; a JSON body cut short cannot be parsed at all).
- The parsing is a pure module (`frontend/src/inspect/inspect.ts`) so the Repeater can reuse it on a request being edited. Everything is still rendered as text, never HTML.

## Further reading

- [PortSwigger — Burp Inspector](https://portswigger.net/burp/documentation/desktop/tools/inspector) — the panel this copies.
- [OWASP WSTG — Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution) — which servers take which copy.
- [OWASP WSTG — Testing for Cookies Attributes](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes) — the checklist behind the flags.
- [MDN — Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie) — every attribute, and the `__Host-`/`__Secure-` prefixes.
- [web.dev — SameSite cookies explained](https://web.dev/articles/samesite-cookies-explained) — Lax by default, and why `None` needs `Secure`.
- [Bishop Fox — An exploration of JSON interoperability vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities) — duplicate keys and parser disagreement.
- [RFC 6265 §5.2 — The Set-Cookie header](https://httpwg.org/specs/rfc6265.html#sane-set-cookie) — how browsers parse attributes (case-insensitive, last one wins).
- [PortSwigger — CSRF and SameSite restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions) — Academy labs on getting around SameSite.
