# 09 — The local root CA: why HTTPS interception needs one

## The idea

A **certificate** is a signed statement: "this public key belongs to `example.com`, signed, Issuer X". A **certificate authority (CA)** is whoever signs it. A client believes the statement only if it trusts the signer.

Trust is a **chain**. A site's leaf certificate is signed by an intermediate CA, the intermediate by a **root CA**, and the root signs itself. The client walks the chain upward, checking each signature, until it reaches a root that is already in its **trust store** (on macOS: the System and login keychains, plus their trust settings). Nothing above the root vouches for it: a root is trusted because the OS, or the user, put it there.

```
example.com leaf  --signed by-->  intermediate CA  --signed by-->  root CA (in the trust store)
```

Each link has rules the verifier checks: dates, the host name in the leaf's Subject Alternative Name, that only certificates marked `CA:true` signed others, and that the leaf may be used for `serverAuth`.

**Interception** breaks this on purpose. When a browser opens `https://example.com` through Sluice, Sluice ends the TLS session itself so it can read the bytes, and opens a second TLS session to the real server. The browser now talks to Sluice, so Sluice must show a certificate for `example.com`. It cannot use the real one: it does not have the site's private key. So it **mints** its own leaf for `example.com`, signed by its own root CA. The browser accepts it only if that root is in the trust store. That is why the user has to install Sluice's CA once, by hand.

## Why it matters

- **A trusted CA key is a master key.** Whoever holds the private key of a root your Mac trusts can mint a certificate for any site (your bank, your mail) that your browser accepts without a warning. Installing a CA is a real security decision, not a setup chore.
- **This has gone wrong in public.** Lenovo shipped laptops with the Superfish adware, which installed one root CA with the **same private key on every machine**; the key was extracted, and anyone could then impersonate any site to any of those laptops.
- **So each install needs its own key, kept secret.** Sluice generates its root on first run (nothing shared between users), never prints or exports the private key, and keeps it encrypted on disk.
- **Platforms limit what a root may sign.** Apple rejects TLS server certificates valid for more than 825 days under a user-installed root, and more than 398 days under a public one; RSA keys must be at least 2048 bits. A leaf that breaks these rules looks like "the CA is broken".
- **Trust failures look like other failures.** An untrusted CA makes the browser abort the handshake, which looks just like certificate pinning or a proxy bug. A trust check that runs first turns that into a clear message.

## What Sluice does

- **Root CA**: RSA 2048, 10-year validity, `CA:true` with **path length 0** (it can sign leaves but not another CA, which limits what a stolen key can create), and a random suffix in its name so each install is distinct in Keychain Access.
- **Shared leaf key**: one leaf RSA key pair is generated once and stored with the CA. Each host gets only a new certificate (random serial, SAN = host, `serverAuth`, about 397 days). Making a 2048-bit RSA key takes tens of milliseconds; doing it per host would stall a page that opens many hosts.
- **Key storage**: `ca.pem` (public) and `ca-keys.enc` (both private keys, mode 0600) live in `~/Library/Application Support/Sluice/ca/`. The keys file is sealed with AES-256-GCM using a key derived (HKDF) from a 32-byte secret held in the login Keychain. The ciphertext is bound to `ca.pem`'s hash, so the keys of one CA do not open next to another CA's certificate. If `ca.pem` exists but its keys are gone, Sluice stops with an error rather than silently minting a new root the user would have to reinstall.
- **Settings**: shows the CA's name and SHA-256 fingerprint (compare it with Keychain Access before you trust anything), **Export CA certificate (PEM)** (certificate only, for Firefox or other tools), and **Install to login keychain**, which runs `security add-trusted-cert -r trustRoot` only when you click it; macOS asks for your password.
- **Trust health check**: two questions. *Installed*: is this exact certificate (by SHA-256) in the login keychain? *Trusted*: does macOS accept a throwaway leaf for `trust-check.sluice.invalid` signed by it? The second goes through Go's `crypto/x509`, which on macOS asks the OS verifier, so it answers what the browser will decide.
- **Removing it**: delete "Sluice Local CA …" in Keychain Access (login keychain, Certificates). Do this if you stop using Sluice.

**Measured** (M3, Apple M3 Max): minting a leaf with the shared key takes about 0.94 ms; making a fresh RSA 2048 key for every host pushes that to about 48 ms. Key generation dominates because an RSA key needs two large random primes, found by trial and error, while minting needs only one signature by the root, which is cheap. (A fresh ECDSA P-256 key is also cheap, about the same 0.9 ms, since it is just a random number and one curve multiplication.) Once minted, a host's leaf is cached, and a cache hit takes about 94 ns. The trade-off: whoever steals the shared leaf key can impersonate every host Sluice ever minted a leaf for, not just one. That matters less than it sounds, because those leaves are only trusted on this Mac, through its local root, and the root key sits next to the leaf key anyway.

## Further reading

- [Wikipedia — Certificate authority](https://en.wikipedia.org/wiki/Certificate_authority) — what a CA does and how browsers decide whom to trust.
- [Wikipedia — Chain of trust](https://en.wikipedia.org/wiki/Chain_of_trust) — leaf, intermediate, root.
- [RFC 5280 — Internet X.509 PKI Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) — basic constraints, path length, key usage, SKI/AKI, path validation.
- [RFC 7093 — Additional methods for generating key identifiers](https://www.rfc-editor.org/rfc/rfc7093) — the SHA-256 key identifier Sluice uses.
- [Apple — Requirements for trusted certificates in iOS 13 and macOS 10.15](https://support.apple.com/en-us/103769) — the 825-day and RSA 2048 rules.
- [Apple — About upcoming limits on trusted certificates](https://support.apple.com/en-us/102028) — the 398-day rule for public roots.
- [PortSwigger — Installing Burp's CA certificate](https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate) — the same step in Burp.
- [mitmproxy — How mitmproxy works](https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/) — a clear walk through CONNECT, TLS termination and minted certificates.
- [Wikipedia — Superfish](https://en.wikipedia.org/wiki/Superfish) — what happens when one CA key is shared across machines.
- [RFC 6761 — Special-Use Domain Names](https://www.rfc-editor.org/rfc/rfc6761) — why `.invalid` is safe for the trust-check probe.
- [Go — crypto/x509](https://pkg.go.dev/crypto/x509) — certificate creation and verification, including the platform verifier.
- [SS64 — macOS `security`](https://ss64.com/mac/security.html) — `add-trusted-cert`, `find-certificate` and friends.
