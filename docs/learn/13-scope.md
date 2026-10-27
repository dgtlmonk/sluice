# 13 — Scope: only send where you are allowed to

## The idea

A proxy has two modes. **Passive**: the browser picks the target and Sluice watches. **Active**: Sluice itself is the client — Repeater resends a request, the Fuzzer fires thousands, an AI tool or MCP client asks for a send. In active mode Sluice decides where packets go, so Sluice is responsible for where they go.

The **scope** is the list of hosts active tools may reach. Anything not on it is refused, in the engine, before a socket opens.

```
active send ──► Scope.Check(host) ──► in list?  ── no ──► refused, never dialled
                                         │ yes
                                         ▼
                                    Scope.Dial ──► origin ──► 3xx Location: X
                                                                   │
                                          Scope.Redirect(X) ◄──────┘  (each hop, again)
```

Sluice's default scope is `localhost`, `127.0.0.1` and `*.test`. `.test` is reserved by RFC 6761: it never resolves on the public internet, so a typo can't reach a real company.

## Why it matters

- **It is the law and the contract.** Sending attack traffic to a system you have no permission to test is unauthorized access in most countries (in the US, the CFAA). Bug bounty programs publish a scope; findings on out-of-scope assets are rejected, and testing them can get you banned. Safe-harbor terms only protect you *inside* scope. A tool that keeps you in scope protects you.
- **Redirects are the classic escape.** An in-scope site answers `302 Location: http://169.254.169.254/latest/meta-data/`. A tool that follows it blindly has just done an SSRF to cloud metadata on someone else's behalf. This is the same bug class you hunt for in BSCP: here the tool must not have it. So every redirect hop is checked again, not only the first URL.
- **URLs lie.** Parsers disagree, and SSRF filters break on the gaps (Orange Tsai, "A New Era of SSRF"):
  - `http://127.0.0.1@evil.example/` — the host is `evil.example`; `127.0.0.1` is a username.
  - `http://evil.example#@127.0.0.1/` — the host is `evil.example`; the rest is a fragment.
  - `http://evil.example\@127.0.0.1/` — browsers read `\` as `/`, so the host is `evil.example`.
  - `http://2130706433/`, `http://0x7f.1/`, `http://127.1/` — all mean `127.0.0.1` to many resolvers.
  - `evil-test` is not `*.test`; `a.test.evil.example` is not either.
- **The UI is not a security boundary.** A check in React can be skipped by any other caller: a script, an MCP tool, a future feature. The engine is the one place every active send passes through, so that is where the check lives.

Rule: when a parser and a check might disagree, refuse the input. Why: an attacker only needs one input that the check reads one way and the network reads another.

## What Sluice does

- **One gate** (`internal/engine/scope.go`): `Scope.Dial` is the only way active tools open a connection. It checks the host first and never resolves or dials a refused one. `Scope.Redirect` resolves each `Location` (absolute, `//host`, `/path`, `../x`, `?q`) and re-checks it, even a same-host hop, because the list may have changed between hops.
- **Patterns**: `host` (exact), an IP (exact; `::ffff:127.0.0.1` counts as `127.0.0.1`), or `*.domain` (every subdomain, not the domain itself, never an IP). Case and one trailing dot are ignored. Ports are not part of a rule.
- **Refused as malformed**, never guessed at: userinfo (`user@host`), backslashes, spaces and control characters, non-ASCII hosts (use punycode), percent-encoded hosts, IPv6 zones, `[127.0.0.1]`, empty or bad ports, schemes other than `http`/`https` (`gopher:`, `file:`, `javascript:`), and any host whose last label is a number but which is not a plain dotted-quad (`127.1`, `2130706433`, `0x7f.0.0.1`, `0177.0.0.1`).
- **The name checked is the name resolved.** Dial looks a host name up *rooted*, with a trailing dot (`a.test.`). Without the dot, the system resolver may retry a name that does not resolve with the machine's DNS search domain appended: on a home network whose search domain is `lan`, `nothere.test` becomes `nothere.test.lan`, a host the check never saw and whoever runs that network's DNS controls. Rule: resolve exactly what you checked. Why: any rewrite between check and connect is a gap an attacker can stand in.
- **"The one gate" is enforced by a test, not just a comment.** Go cannot stop a package from calling `net.Dial`, so `TestOnlyScopeDialsActively` scans the source: any new dial, DNS lookup or HTTP client outside a short allow-list (the gate itself, and the passive proxy's upstream dials) fails the build's tests.
- **Errors name the host only**, never the URL, so a password or token in a URL cannot land in a log.
- **Settings → Scope** edits the list; it applies live and is saved to `scope.json` (mode 0600) next to `bypass.json`. No file yet means the default list. A broken file fails closed: an empty scope, which refuses every active send, and Settings says why until you save a good list. Over-broad patterns (`*.com`, `0.0.0.0`, `::`) are allowed but flagged. "Reset to default" only fills the editor; nothing changes until you press Save.
- **Passive proxying is not limited.** Browsing through Sluice records everything; scope only stops Sluice from *sending* on its own.
- **Tests**: every rule above has a case in `internal/engine/scope_test.go`, and the dial and redirect paths run against `internal/testorigin` (its `/redirect?to=` endpoint plays the in-scope site that tries to bounce you out).
- **Not yet**: the IP a host *name* resolves to is not checked. An in-scope name whose DNS points somewhere else (DNS rebinding) gets through. Tracked in SPEC.md "Known gaps".

For PortSwigger labs: add the lab's host (or `*.web-security-academy.net`) to the scope before using Repeater on it.

## Further reading

- [PortSwigger — Burp target scope](https://portswigger.net/burp/documentation/desktop/tools/target/scope) — the same feature in Burp.
- [PortSwigger — Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf) — the bug class a redirect escape is; Academy labs included.
- [PortSwigger — URL validation bypass cheat sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet) — the tricks a scope check must survive.
- [OWASP — SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — allow-lists, redirects and DNS pinning, from the defender's side.
- [OWASP Top 10 2021 — A10 SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) — why SSRF earned its own category.
- [Orange Tsai — A New Era of SSRF (Black Hat USA 2017, PDF)](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) — parser differentials: `@`, `#`, `\` and friends.
- [AWS — Instance metadata service (IMDSv2)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) — what `169.254.169.254` hands out, and why it is the classic SSRF target.
- [WHATWG URL Standard](https://url.spec.whatwg.org/) — how browsers parse URLs, including the IPv4 "ends in a number" rule.
- [RFC 3986 — URI syntax](https://www.rfc-editor.org/rfc/rfc3986) — authority, userinfo, and reference resolution (§5) used for redirects.
- [RFC 9110 §4.2.4 — http(s) userinfo is deprecated](https://www.rfc-editor.org/rfc/rfc9110) — why `user@host` is refused.
- [resolv.conf(5) — search list and ndots](https://man7.org/linux/man-pages/man5/resolv.conf.5.html) — how a resolver appends search domains to a name, and why a trailing dot stops it.
- [RFC 6761 §6.2 — the .test TLD](https://www.rfc-editor.org/rfc/rfc6761) — why `*.test` is a safe default.
- [HackerOne — Scope](https://docs.hackerone.com/en/articles/8410331-scope) — how programs define in-scope assets.
- [HackerOne — Disclosure guidelines](https://www.hackerone.com/disclosure-guidelines) — the rules researchers agree to.
- [Bugcrowd — Standard disclosure terms](https://www.bugcrowd.com/resources/essentials/standard-disclosure-terms/) — scope and safe harbor in Bugcrowd programs.
- [disclose.io](https://disclose.io/) — standard safe-harbor language, and what it does and does not cover.
- [US DOJ — CFAA charging policy (2022)](https://www.justice.gov/opa/pr/department-justice-announces-new-policy-charging-cases-under-computer-fraud-and-abuse-act) — good-faith research, and its limits.
