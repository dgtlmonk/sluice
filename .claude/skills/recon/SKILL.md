---
name: recon
description: Verify a Sluice feature in the real app with real clients (curl matrix + a real Chromium browser), then inspect the app's History for anomalies before calling the feature done. Use after any engine/TLS/UI change lands, before telling the user "it works", and when the user says "recon", "verify in the app", or "check it for real". Unit tests and a single curl are not enough: real browsers preconnect, retry, use h2/ALPN, and send background traffic that tests never produce.
---

# Recon: real-client verification for Sluice

Why this exists: m3-bypass passed 394 tests, review grade B, and one curl smoke test. The first real
Brave session flagged a host as "pinning suspected" because Chromium closes unused preconnects with a
bare EOF. Tests use well-behaved clients; real ones do not. Recon is the step that catches that.

## Preconditions (check, do not assume)

1. No agent is editing Go right now (never rebuild mid-workflow).
2. Rebuild AFTER the last edit: `wails build -m -nosyncgomod` from the repo root. The binary must be newer
   than the newest `*.go` / `frontend/src` change (`stat -f %m`). "Running" is not "current".
3. Relaunch: `pkill -f "sluice.app/Contents/MacOS"; SLUICE_PROXY_ADDR=127.0.0.1:8081 open build/bin/sluice.app`.
   Port 8080 belongs to OrbStack.
4. For a clean History, use a throwaway project: `SLUICE_PROJECT=$SCRATCH/recon.sluice`.
5. CA trust state matters for TLS features: note what Settings says (installed / trusted).

## Drive real traffic

Run what the feature touches; always include at least one real browser.

**curl matrix** (fast, scriptable; record exit code, `%{http_code}`, `%{http_version}`, issuer):
```
curl -sv -x 127.0.0.1:8081 https://example.com/ -o /dev/null          # decrypted path
curl -sv -x 127.0.0.1:8081 --http2 https://example.com/ -o /dev/null  # ALPN downgrade
curl -sv -x 127.0.0.1:8081 http://example.com/ -o /dev/null           # plain HTTP
curl -sv -x 127.0.0.1:8081 --cacert /etc/ssl/cert.pem https://example.com/ -o /dev/null  # client rejects Sluice cert
```

**Real Chromium (Brave), headless, isolated profile** — exercises preconnect, h2 offers, background
component/telemetry traffic:
```
"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" --headless=new \
  --proxy-server=127.0.0.1:8081 --user-data-dir="$SCRATCH/brave-recon" \
  --dump-dom https://example.com/ > "$SCRATCH/dom.html"
```
Run it twice (second run reuses the profile: different connection pattern). Never touch the user's real
Brave profile. Delete `$SCRATCH/brave-recon` after.

## Inspect the app

Screenshot the app window and read it:
```
screencapture -x -o -l "$(osascript -e 'tell application "System Events" to get id of window 1 of process "sluice"' 2>/dev/null)" "$SCRATCH/recon.png" \
  || screencapture -x "$SCRATCH/recon.png"
```
Then Read the PNG. Click into suspicious rows only through the user, or report them.

## Anomaly checklist (any hit = not done)

- Status `0` or empty on a row without a stated reason.
- Red `proxy error` on traffic a normal browser produced.
- `pinning suspected` on a host that also has successful decrypted rows.
- Scheme wrong for the port (`http://` on a :443 CONNECT).
- Rows missing: browser loaded the page but no matching GET row.
- Duplicate rows, out-of-order timestamps, truncated columns hiding values.
- Status bar: Dropped > 0, or a "history incomplete" error.
- Anything secret visible where it should be redacted.

## Report

Write `$EVIDENCE/<task>-recon.md`: build time vs last edit, commands run with results, screenshot path,
checklist with pass/fail per line. Tell the user only: what was checked, what failed, what you are fixing.
