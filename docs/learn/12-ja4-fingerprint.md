# 12 — JA4: fingerprinting the TLS client, from the defender's side

## The idea

Before any encryption, every TLS client says hello in cleartext, and every TLS library says it a little differently: which versions, which cipher suites in what order, which extensions, which signature algorithms, which ALPN protocols. Those choices are baked into the library, not the user. Chrome 130 on any laptop says hello the same way; Python's `requests`, Go's `net/http` and `curl` each have their own voice.

**JA4** (FoxIO, part of the JA4+ suite) turns that hello into a short, stable string:

```
t13d1516h2_8daaf6152771_e5627efa2ab1
│││ │ │ │  │            └ c: hash of sorted extensions + signature algorithms
│││ │ │ │  └ b: hash of sorted cipher suites
│││ │ │ └ first/last char of first ALPN value (h2)
│││ │ └ 16 extensions
│││ └ 15 cipher suites
││└ d = SNI present (domain), i = no SNI (IP)
│└ 13 = TLS 1.3
└ t = TCP
```

GREASE values (random reserved numbers clients add on purpose, RFC 8701) are dropped, and the lists are **sorted** before hashing. Sorting matters: Chrome shuffles its extension order on every connection, which made the older JA3 fingerprint change constantly; JA4 stays the same.

## Why it matters

- **User-Agent is a claim; JA4 is evidence.** A User-Agent header is one line any script can set. The ClientHello comes from the TLS library actually in use. A request saying "Chrome on macOS" whose JA4 is Python's or Go's is not Chrome: a scraper, a credential-stuffing bot, or malware using a browser disguise.
- **Defenders already use it.** CDNs and bot-management products expose JA4 to rules; IDS tools (Zeek, Suricata, Wireshark) compute it; threat-intel feeds list fingerprints of known malware families. A tester who records JA4 can check what their own tooling looks like to those defenses.
- **It works when nothing else is visible.** For a raw tunnel (page 11) Sluice never sees the HTTP inside, but the hello, and so the JA4, is still there.
- **It is not identity.** Many users share one JA4 (everyone on the same browser build), and a careful attacker can mimic a browser's hello with uTLS-style libraries. Treat it as a strong signal to combine with others, never as proof on its own.

## What Sluice does

- **Computed for every CONNECT**, decrypted or tunnelled, from the ClientHello Sluice already reads to make the bypass decision (`internal/engine/ja4.go`, only the `ja4` part of JA4+).
- **Stored on the exchange**: every request inside a decrypted tunnel carries its tunnel's JA4; a tunnelled or failed CONNECT row carries it too. The detail pane shows it above the request/response columns, next to the tunnel reason.
- **Tested against the spec's own vectors**: the Chrome example (`t13d1516h2_8daaf6152771_e5627efa2ab1`, rebuilt as a ClientHello with GREASE and a shuffled extension order), the no-signature-algorithms vector, and every ALPN edge case the spec prints. No test touches the network.
- **How to use it**: open an HTTPS row, compare the JA4 with the `User-Agent` request header. Same browser, same JA4 across rows; a different JA4 under the same User-Agent is worth a look.
- **Not yet**: the JA4 is kept in memory for this session's rows only (no store column yet); no lookup against a fingerprint database; no automatic "User-Agent mismatch" finding (a candidate for the M5 passive rules).

## Further reading

- [FoxIO — JA4+ repository](https://github.com/FoxIO-LLC/ja4) — the suite, reference implementations and Wireshark/Zeek plugins.
- [FoxIO — JA4 technical details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) — the exact algorithm and the test vectors Sluice uses.
- [Salesforce Engineering — TLS fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/) — the predecessor, and the defender's reasoning behind it.
- [Cloudflare — JA3/JA4 fingerprint](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/) — how a CDN exposes JA4 to bot rules.
- [RFC 8701 — GREASE](https://www.rfc-editor.org/rfc/rfc8701) — why clients add random values, and why fingerprints must drop them.
- [tlsfingerprint.io](https://tlsfingerprint.io/) — a public collection of real-world ClientHello fingerprints.
