import { useEffect, useState } from 'react'
import { ExchangeDetail, type ExchangeView, type MessageView } from '../bridge'
import { useExchangeStore } from '../store/exchanges'

type Tab = 'raw' | 'headers'
type Loaded = { view: ExchangeView } | { error: string }

/**
 * Request/response for the selected exchange, fetched from the engine on demand.
 *
 * SECURITY: everything shown here is captured traffic, i.e. untrusted input.
 * It is rendered only as React text children (escaped by React), never as
 * HTML: no dangerouslySetInnerHTML, no innerHTML, no markdown. The Go side
 * has already made control characters and binary bodies visible as text.
 */
export function DetailPane() {
  const selected = useExchangeStore((s) => s.selected)
  const [loaded, setLoaded] = useState<Loaded | null>(null)
  const [tab, setTab] = useState<Tab>('raw')

  useEffect(() => {
    setLoaded(null)
    if (!selected) return
    let stale = false
    ExchangeDetail(selected.id)
      .then((view) => !stale && setLoaded({ view }))
      .catch((err) => !stale && setLoaded({ error: String(err) }))
    return () => {
      stale = true
    }
  }, [selected])

  if (!selected) {
    return <section className="detail detail-empty">Select a row to see its request and response.</section>
  }

  const view = loaded && 'view' in loaded ? loaded.view : null
  return (
    <section className="detail detail-tabbed">
      <nav className="detail-tabs" role="tablist">
        {(['raw', 'headers'] as const).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
            {t === 'raw' ? 'Raw' : 'Headers'}
          </button>
        ))}
        {loaded && 'error' in loaded && <span className="detail-error">error: {loaded.error}</span>}
        {view?.proxyError && <span className="detail-error">proxy error: {view.proxyError}</span>}
      </nav>
      <div className="detail-cols">
        <div className="detail-col">
          <header>
            Request <span className="muted">#{selected.id}</span>
          </header>
          {view && <Message m={view.request} tab={tab} />}
        </div>
        <div className="detail-col">
          <header>
            Response{' '}
            <span className="muted">
              {selected.status} · {selected.respSize.toLocaleString()} B · {selected.durationMs} ms
            </span>
          </header>
          {view && <Message m={view.response} tab={tab} />}
        </div>
      </div>
    </section>
  )
}

function Message({ m, tab }: { m: MessageView; tab: Tab }) {
  if (!m.captured) return <pre className="muted">(not captured)</pre>
  return tab === 'raw' ? <RawView m={m} /> : <HeaderTable m={m} />
}

function RawView({ m }: { m: MessageView }) {
  return (
    <div className="detail-scroll">
      <BodyNotice m={m} />
      <pre>
        {m.head}
        {m.bodyEncoding === 'hex' && m.bodyShown > 0 && <span className="muted">(binary body, hex view){'\n'}</span>}
        {m.body}
      </pre>
    </div>
  )
}

function BodyNotice({ m }: { m: MessageView }) {
  if (!m.bodyViewTruncated && !m.bodyTruncated) return null
  return (
    <div className="detail-notice">
      {m.bodyViewTruncated && (
        <div>
          Truncated in view: showing {m.bodyShown.toLocaleString()} of {m.bodyBytes.toLocaleString()} stored body bytes.
        </div>
      )}
      {m.bodyTruncated && (
        <div>Stored body was truncated at the storage cap ({m.bodyBytes.toLocaleString()} bytes kept); the full body was forwarded.</div>
      )}
    </div>
  )
}

function HeaderTable({ m }: { m: MessageView }) {
  return (
    <div className="detail-scroll">
      <div className="detail-startline">{m.startLine}</div>
      <table className="header-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {/* Index keys: duplicates are legal and kept in wire order. */}
          {m.headers.map((h, i) => (
            <tr key={i} className={h.malformed ? 'malformed' : undefined}>
              <td>{h.malformed ? '(malformed line)' : h.name}</td>
              <td>{h.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
