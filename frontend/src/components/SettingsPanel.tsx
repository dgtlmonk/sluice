import { useCallback, useEffect, useState } from 'react'
import { type CAState, caInfo, caTrust, exportCA, installCA, type TrustState } from '../bridge'

type Props = { onClose: () => void }

/** Settings: for now the root CA section (export, install, trust check). */
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

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section className="modal settings" role="dialog" aria-label="Settings" onClick={(e) => e.stopPropagation()}>
        <header className="modal-head">
          <h2>Settings</h2>
          <button onClick={onClose} aria-label="Close">
            Close
          </button>
        </header>

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
