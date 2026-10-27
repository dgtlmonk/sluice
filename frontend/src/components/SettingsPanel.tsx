import { useCallback, useEffect, useRef, useState } from 'react'
import {
  bypassHosts,
  type CAState,
  caInfo,
  caTrust,
  defaultScopeHosts,
  exportCA,
  forgetTLSHost,
  installCA,
  savePrefs,
  type ScopeState,
  scopeHosts,
  setBypassHosts,
  setScopeHosts,
  type TLSHostState,
  tlsHosts,
  type TrustState,
} from '../bridge'
import { FONT_SIZES, type Theme, usePrefsStore } from '../store/prefs'

type Props = { onClose: () => void }

/** Settings: appearance, the root CA (export, install, trust check), the scope list and the TLS bypass list. */
export function SettingsPanel({ onClose }: Props) {
  const [info, setInfo] = useState<CAState | null>(null)
  const [trust, setTrust] = useState<TrustState | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const recheck = useCallback(async () => {
    setTrust(null)
    try {
      setTrust(await caTrust())
    } catch (err) {
      setError(`trust check: ${String(err)}`)
    }
  }, [])

  useEffect(() => {
    caInfo()
      .then((i) => {
        setInfo(i)
        if (i.ready) void recheck()
      })
      .catch((err) => setError(String(err)))
  }, [recheck])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const act = async (label: string, action: () => Promise<string | null>) => {
    setBusy(label)
    setError(null)
    setMessage(null)
    try {
      const msg = await action()
      if (msg) setMessage(msg)
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(null)
    }
  }

  const onExport = () =>
    act('export', async () => {
      const path = await exportCA()
      return path ? `Saved certificate to ${path}` : null
    })

  const onInstall = () =>
    act('install', async () => {
      await installCA()
      await recheck()
      return 'Installed to the login keychain.'
    })

  // Close on a backdrop click only when the press also started there. A text
  // selection dragged out of the panel ends on the backdrop, and the browser
  // fires click on the common ancestor, which would close the panel.
  const pressedBackdrop = useRef(false)

  return (
    <div
      className="modal-backdrop"
      onPointerDown={(e) => {
        pressedBackdrop.current = e.target === e.currentTarget
      }}
      onClick={(e) => {
        if (pressedBackdrop.current && e.target === e.currentTarget) onClose()
      }}
    >
      <section className="modal settings" role="dialog" aria-label="Settings">
        <header className="modal-head">
          <h2>Settings</h2>
          <button onClick={onClose} aria-label="Close">
            Close
          </button>
        </header>

        <AppearanceSection />

        <h3>Root CA</h3>
        <p className="muted">
          Sluice signs a certificate for each HTTPS site with this local CA. Browsers only accept those certificates once you trust the CA. Anyone with its private key could impersonate any
          site to this Mac, so the key never leaves Sluice.
        </p>

        {info === null ? (
          <p className="muted">Loading…</p>
        ) : !info.ready ? (
          <p className="error-text">CA unavailable: {info.error}</p>
        ) : (
          <dl className="kv">
            <dt>Name</dt>
            <dd>{info.subject}</dd>
            <dt>SHA-256</dt>
            <dd className="mono wrap">{info.fingerprint}</dd>
            <dt>Expires</dt>
            <dd>{info.notAfter ? new Date(info.notAfter).toLocaleDateString() : ''}</dd>
            <dt>Folder</dt>
            <dd className="mono wrap">{info.dir}</dd>
            <dt>Trust</dt>
            <dd>
              <TrustBadge trust={trust} />
            </dd>
          </dl>
        )}

        <div className="actions">
          <button className="primary" disabled={!info?.ready || busy !== null || trust?.trusted === true} onClick={onInstall}>
            {busy === 'install' ? 'Waiting for password…' : 'Install to login keychain'}
          </button>
          <button disabled={!info?.ready || busy !== null} onClick={onExport}>
            Export CA certificate (PEM)
          </button>
          <button disabled={!info?.ready || busy !== null} onClick={() => void recheck()}>
            Check trust
          </button>
        </div>
        {message && <p className="ok-text">{message}</p>}
        {error && <p className="error-text">{error}</p>}
        <p className="muted small">Firefox uses its own certificate store: import the exported PEM there, or set security.enterprise_roots.enabled to true.</p>

        <ScopeSection />

        <BypassSection />
      </section>
    </div>
  )
}

function TrustBadge({ trust }: { trust: TrustState | null }) {
  if (trust === null) return <span className="muted">checking…</span>
  if (trust.trusted) return <span className="ok-text">Installed and trusted</span>
  return (
    <span className="warn-text" title={trust.detail}>
      {trust.installed ? 'Installed, but not trusted' : 'Not installed'}
    </span>
  )
}

/**
 * Scope list editor (one pattern per line). The list lives in the engine:
 * every active send and every redirect hop is checked there, so this editor
 * only changes the list, it never decides what is allowed.
 */
function ScopeSection() {
  const [text, setText] = useState('')
  const [saved, setSaved] = useState('')
  const [defaults, setDefaults] = useState('')
  const [warnings, setWarnings] = useState<string[]>([])
  const [loadError, setLoadError] = useState('')
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null)

  const show = (s: ScopeState) => {
    setText(s.hosts.join('\n'))
    setSaved(s.hosts.join('\n'))
    setWarnings(s.warnings)
    setLoadError(s.loadError)
  }

  useEffect(() => {
    scopeHosts()
      .then(show)
      .catch((err) => setStatus({ ok: false, msg: String(err) }))
    defaultScopeHosts()
      .then((l) => setDefaults(l.join('\n')))
      .catch((err) => setStatus({ ok: false, msg: String(err) }))
  }, [])

  const save = async () => {
    setStatus(null)
    try {
      const s = await setScopeHosts(text.split('\n'))
      show(s)
      setStatus(
        s.hosts.length === 0
          ? { ok: false, msg: 'Saved an empty scope: every active send is refused.' }
          : { ok: true, msg: `Saved ${s.hosts.length} pattern${s.hosts.length === 1 ? '' : 's'}.` },
      )
    } catch (err) {
      setStatus({ ok: false, msg: String(err) })
      // "Applied, but not saved" still changed the live list. Re-read the
      // baseline, but keep the editor text: a refused pattern must stay
      // on screen for the user to fix.
      scopeHosts()
        .then((s) => {
          setSaved(s.hosts.join('\n'))
          setWarnings(s.warnings)
          setLoadError(s.loadError)
        })
        .catch(() => {})
    }
  }

  // Reset only fills the editor: nothing changes until Save, so one click
  // can never wipe a custom list. Save is the confirmation.
  const onReset = () => {
    setText(defaults)
    setStatus({ ok: true, msg: 'Default list loaded into the editor. Save scope to apply it; your custom hosts are not saved in it.' })
  }

  return (
    <>
      <h3>Scope</h3>
      <p className="muted">
        Active tools (Repeater now; Fuzzer and MCP later) only send to these hosts. The engine refuses anything else, including a redirect that leaves the list. Browser traffic
        through the proxy is never limited. One per line: <code>host</code>, an IP, or <code>*.domain</code> (subdomains only). A rule covers every port.
      </p>
      {loadError && <p className="error-text">{loadError}</p>}
      <textarea
        className="scope-editor"
        aria-label="Scope hosts"
        spellCheck={false}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={'localhost\n127.0.0.1\n*.test\n*.web-security-academy.net'}
      />
      <div className="actions">
        <button className="primary" disabled={text === saved && !loadError} onClick={() => void save()}>
          Save scope
        </button>
        <button disabled={defaults === '' || text === defaults} onClick={onReset} title="Load localhost, 127.0.0.1 and *.test into the editor (Save to apply)">
          Reset to default
        </button>
      </div>
      {status && <p className={status.ok ? 'ok-text' : 'error-text'}>{status.msg}</p>}
      {warnings.length > 0 && (
        <ul className="warn-text small">
          {warnings.map((w) => (
            <li key={w}>Broad: {w}.</li>
          ))}
        </ul>
      )}
      <p className="muted small">Only test hosts you own or have written permission to test. For a PortSwigger lab, add its lab host.</p>
    </>
  )
}

/**
 * Bypass list editor (one pattern per line) plus the hosts the engine
 * decided to tunnel on its own. Tunnelled hosts are never decrypted: only
 * their JA4 fingerprint and byte counts are recorded.
 */
function BypassSection() {
  const [text, setText] = useState('')
  const [saved, setSaved] = useState('')
  const [hosts, setHosts] = useState<TLSHostState[]>([])
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null)

  const refreshHosts = useCallback(() => {
    tlsHosts()
      .then(setHosts)
      .catch((err) => setStatus({ ok: false, msg: String(err) }))
  }, [])

  useEffect(() => {
    bypassHosts()
      .then((l) => {
        setText(l.join('\n'))
        setSaved(l.join('\n'))
      })
      .catch((err) => setStatus({ ok: false, msg: String(err) }))
    refreshHosts()
  }, [refreshHosts])

  const save = async (lines: string[]) => {
    setStatus(null)
    try {
      const norm = await setBypassHosts(lines)
      setText(norm.join('\n'))
      setSaved(norm.join('\n'))
      setStatus({ ok: true, msg: `Saved ${norm.length} pattern${norm.length === 1 ? '' : 's'}.` })
    } catch (err) {
      setStatus({ ok: false, msg: String(err) })
    }
  }

  const onSave = () => save(text.split('\n'))
  // Learned flags last only for this session; the bypass list is saved.
  const onKeep = (host: string) => save([...saved.split('\n'), host])

  const onForget = async (host: string) => {
    await forgetTLSHost(host)
    refreshHosts()
  }

  return (
    <>
      <h3>TLS bypass</h3>
      <p className="muted">
        Hosts listed here are tunnelled raw: Sluice passes the encrypted bytes through without decrypting them. One per line, <code>host</code> or <code>*.domain</code> (subdomains only).
      </p>
      <textarea
        className="bypass-editor"
        aria-label="Bypass hosts"
        spellCheck={false}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={'example.com\n*.apple.com'}
      />
      <div className="actions">
        <button className="primary" disabled={text === saved} onClick={() => void onSave()}>
          Save bypass list
        </button>
      </div>
      {status && <p className={status.ok ? 'ok-text' : 'error-text'}>{status.msg}</p>}

      <h3>Tunnelled automatically</h3>
      {hosts.length === 0 ? (
        <p className="muted small">None this session. Hosts appear here when a client rejects Sluice&apos;s certificate while the CA is trusted (likely pinning), or an origin refuses HTTP/1.1.</p>
      ) : (
        <ul className="tls-hosts">
          {hosts.map((h) => (
            <li key={h.host}>
              <span className="mono">{h.host}</span>
              <span className={h.reason === 'pinning suspected' ? 'warn-text' : 'muted'}>{h.reason}</span>
              <button onClick={() => void onKeep(h.host)} title="Keep tunnelling this host after restart">
                Add to bypass list
              </button>
              <button onClick={() => void onForget(h.host)} title="Decrypt this host again on the next connection">
                Forget
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  )
}

const THEMES: { id: Theme; label: string }[] = [
  { id: 'system', label: 'System' },
  { id: 'dark', label: 'Dark' },
  { id: 'light', label: 'Light' },
]

/**
 * Theme and text size. Same source of truth as View in the menu bar: the
 * change goes to Go, which saves it and broadcasts it back to the UI.
 */
function AppearanceSection() {
  const prefs = usePrefsStore((s) => s.prefs)
  const [error, setError] = useState<string | null>(null)

  const change = (next: Partial<typeof prefs>) => {
    setError(null)
    savePrefs({ ...prefs, ...next }).catch((err) => setError(String(err)))
  }

  return (
    <>
      <h3>Appearance</h3>
      <div className="appearance">
        <label htmlFor="pref-theme">Theme</label>
        <select id="pref-theme" value={prefs.theme} onChange={(e) => change({ theme: e.target.value as Theme })}>
          {THEMES.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
        <label htmlFor="pref-font">Text size</label>
        <select id="pref-font" value={prefs.fontSize} onChange={(e) => change({ fontSize: Number(e.target.value) })}>
          {FONT_SIZES.map((n) => (
            <option key={n} value={n}>
              {n} px
            </option>
          ))}
        </select>
      </div>
      <p className="muted small">System follows macOS. View in the menu bar also has Bigger Text (⌘=), Smaller Text (⌘−) and Actual Size (⌘0).</p>
      {error && <p className="error-text">{error}</p>}
    </>
  )
}
