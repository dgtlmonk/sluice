# 07 — Raw versus parsed: what the detail pane shows, and why

## The idea

An HTTP message can be shown two ways:

- **Raw**: the bytes exactly as they crossed the wire. Start line, header lines, the blank line, then the body, with chunk framing (`5\r\nhello\r\n0\r\n\r\n`) left in.
- **Parsed**: a structured view, such as a table of header names and values, or a decoded body.

A parsed view is an *interpretation*. Someone wrote code that decided what each byte means. A security tool shows the raw bytes first because interpretations differ, and the differences are where bugs live.

Header order and duplicates are part of the raw truth. RFC 9110 §5.3 lets a field appear more than once. Two `Set-Cookie` lines are normal. Two `Content-Length` lines, or `Transfer-Encoding` next to `Content-Length`, are how request smuggling works ([02](02-request-smuggling.md)). A view that stores headers in a map (one value per name, in no fixed order) quietly hides exactly the case you need to see.

## Why it matters

- **"What did the server actually get?"** Browsers' DevTools often show a cleaned-up view: headers normalised, bodies decoded, chunks joined. That is fine for debugging an app. It is wrong for testing parsers, because the cleaning is the thing under test.
- **Wire order and duplicates are evidence.** `X-Forwarded-For: a` then `X-Forwarded-For: b` means one thing to a server that takes the first value and another to one that takes the last. A header table must keep both lines, in order.
- **Invisible bytes lie.** A lone CR, a NUL, or a Unicode right-to-left override (U+202E) can make text *look* different from what it is (the "Trojan Source" trick). The view must make them visible, not pass them to the screen.
- **Captured traffic is hostile input to the tool itself.** A response body can be `<img src=x onerror=...>`. If the tool renders it as HTML, the attacker's script runs *inside the security tool*. In a desktop app with native bindings, that script could call into the app. This is stored XSS where the victim is the tester. The rule: captured bytes are only ever shown as text.
- **Binary must not break the UI.** Images, compressed bodies and protobuf are not text. Pushing invalid UTF-8 into a text view gives replacement characters at best and a broken layout at worst. A hex dump shows every byte honestly.

## What Sluice does

- **Raw tab**: the head and body as stored. CRLF is shown as a newline; every other control character, invalid UTF-8 byte, and invisible formatting character (bidi overrides, zero-width chars) is shown as an escape such as `\x0d`, `\x00` or `\u{202e}`. A body that is not valid UTF-8 is shown as a hex dump (offset, hex bytes, ASCII column).
- **Large bodies**: the pane gets at most the first 256 KiB of a body, with a "truncated in view, showing X of Y bytes" notice. If the *stored* copy was cut at the 32 MB storage cap, the pane says so too ([05](05-storage-path.md)).
- **Headers tab**: request and response header tables, in wire order, duplicates kept. The split is done in Go and is deliberately lenient. The store can hold heads the strict engine parser rejected, and a viewer must show those rather than fail. A line with no colon, or an obsolete folded line (starting with a space or tab), is shown and flagged "malformed", not dropped or merged.
- **No HTML, ever**: the React pane renders captured data only as text children, which React escapes. No `dangerouslySetInnerHTML`, no `innerHTML`, no markdown rendering. The Go side makes the data display-safe, and the UI still treats it as untrusted.
- The detail binding carries captured traffic only. It never includes the database key or other app secrets. Captured auth headers are shown unredacted here, because this is the user's own view of their own store. Redaction applies to paths that leave it (exports, MCP, LLMs).

## Further reading

- [RFC 9110 §5.3 — Field order](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3) — when repeated fields can be combined, and why order matters.
- [RFC 9112 §5.2 — Obsolete line folding](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.2) — the `obs-fold` lines Sluice flags.
- [RFC 6265 — HTTP State Management (cookies)](https://httpwg.org/specs/rfc6265.html) — why `Set-Cookie` is never combined into one line.
- [PortSwigger — HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) — what duplicate framing headers make possible.
- [PortSwigger — Burp HTTP history](https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history) — how Burp presents captured traffic.
- [OWASP — Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/) — the attack class, including stored XSS.
- [OWASP — XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — output encoding and safe sinks.
- [React — dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html) — the one escape hatch the pane never uses.
- [Trojan Source](https://trojansource.codes/) — how bidi control characters make text read differently from what it is.
- [Unicode UAX #9 — Bidirectional Algorithm](https://www.unicode.org/reports/tr9/) — the rules those characters exploit.
