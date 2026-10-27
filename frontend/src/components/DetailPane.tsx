import { useEffect, useMemo, useState } from 'react'
import { ExchangeDetail, ExchangeTLS, type ExchangeTLSState, type ExchangeView, type MessageView } from '../bridge'
import { useStored } from '../hooks/useStored'
import type { ExchangeContext } from '../inspect/inspect'
import { useExchangeStore } from '../store/exchanges'
import { statusText } from '../view/status'
import { Inspector } from './Inspector'
import { Splitter, useSplit } from './Splitter'

type Tab = 'raw' | 'headers'
const asTab = (v: unknown): Tab | undefined => (v === 'raw' || v === 'headers' ? v : undefined)
// Grouped: Response and Inspector share the right column as two tabs, so the
// request stays in view while you read either. Split: three columns.
type Layout = 'grouped' | 'split'
const asLayout = (v: unknown): Layout | undefined => (v === 'grouped' || v === 'split' ? v : undefined)
type RightPane = 'response' | 'inspector'
const asRightPane = (v: unknown): RightPane | undefined => (v === 'response' || v === 'inspector' ? v : undefined)
type Loaded = { view: ExchangeView; tls: ExchangeTLSState } | { error: string }

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
  const [tab, setTab] = useStored<Tab>('sluice.detail.tab', 'raw', asTab)
  const [layout, setLayout] = useStored<Layout>('sluice.detail.layout', 'grouped', asLayout)
  const [right, setRight] = useStored<RightPane>('sluice.detail.right', 'response', asRightPane)
  const cols = useSplit('sluice.split.reqres', 0.5, 0.15, 0.85)
  const side = useSplit('sluice.split.inspector', 0.7, 0.3, 0.85)

  useEffect(() => {
    setLoaded(null)
    if (!selected) return
    let stale = false
    Promise.all([ExchangeDetail(selected.id), ExchangeTLS(selected.id)])
      .then(([view, tls]) => !stale && setLoaded({ view, tls }))
      .catch((err) => !stale && setLoaded({ error: String(err) }))
    return () => {
      stale = true
    }
  }, [selected])

  const tunnel = loaded && 'tls' in loaded ? (loaded.tls.tunnel ?? '') : ''
  const ja4 = loaded && 'tls' in loaded ? (loaded.tls.ja4 ?? '') : ''
  const ctx = useMemo<ExchangeContext>(
    () => ({ scheme: selected?.scheme ?? '', host: selected?.host ?? '', port: selected?.port ?? 0, tunnel, ja4 }),
    [selected, tunnel, ja4],
  )

  if (!selected) {
    return <section className="detail detail-empty">Select a row to see its request and response.</section>
  }

  const view = loaded && 'view' in loaded ? loaded.view : null
  const tls = loaded && 'tls' in loaded ? loaded.tls : null
  const error = loaded && 'error' in loaded ? loaded.error : null
  const split = layout === 'split'
  const colStyle = (fraction: number) => ({
    // Pixel floors give way to a share of the width (min()) so a narrow
    // pane shrinks every column instead of scrolling sideways.
    gridTemplateColumns: `minmax(min(160px, 45%), ${fraction}fr) auto minmax(min(160px, 45%), ${1 - fraction}fr)`,
  })
  const responseMeta = (
    <span className="muted">
      {statusText(selected.status)} · {selected.respSize.toLocaleString()} B · {selected.durationMs} ms
    </span>
  )
  const request = (
    <div className="detail-col">
      <header>
        Request <span className="muted">#{selected.id}</span>
      </header>
      {view && <Message m={view.request} tab={tab} />}
    </div>
  )
  const inspector = <Inspector view={view} ctx={ctx} error={error} asTab={!split} />

  // Grouped: the right column's header is a small tab bar, Response | Inspector.
  const grouped = (
    <div className="detail-col">
      <header className="detail-col-tabs">
        <div role="tablist" aria-label="Right pane">
          {(['response', 'inspector'] as const).map((p) => (
            <button
              key={p}
              id={`detail-right-${p}`}
              role="tab"
              aria-selected={right === p}
              aria-controls={p === 'inspector' ? 'detail-panel-inspector' : 'detail-panel-response'}
              className={right === p ? 'active' : ''}
              onClick={() => setRight(p)}
            >
              {p === 'response' ? 'Response' : 'Inspector'}
            </button>
          ))}
        </div>
        {right === 'response' && responseMeta}
      </header>
      {/* Both stay mounted and only hide, so the Inspector keeps its Raw
          values toggle, paging and expanded rows across tab switches. */}
      <div className="detail-col-panel" hidden={right !== 'inspector'}>
        {inspector}
      </div>
      <div id="detail-panel-response" role="tabpanel" aria-labelledby="detail-right-response" className="detail-col-panel" hidden={right !== 'response'}>
        {view && <Message m={view.response} tab={tab} />}
      </div>
    </div>
  )

  return (
    <section className="detail detail-tabbed">
      <nav className="detail-tabs">
        <div className="detail-tablist" role="tablist" aria-label="Message view">
          {(['raw', 'headers'] as const).map((t) => (
            <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
              {t === 'raw' ? 'Raw' : 'Headers'}
            </button>
          ))}
        </div>
        {error !== null && <span className="detail-error">error: {error}</span>}
        {view?.proxyError &&
          (tls?.unused ? (
            // A silently abandoned CONNECT (browser preconnect) is not a failure.
            <span className="detail-note">{view.proxyError}</span>
          ) : (
            <span className="detail-error">proxy error: {view.proxyError}</span>
          ))}
        <button
          className={`detail-layout-toggle${split ? ' active' : ''}`}
          aria-pressed={split}
          title="On: Request, Response and Inspector as three columns. Off: Response and Inspector share one column as tabs."
          onClick={() => setLayout(split ? 'grouped' : 'split')}
        >
          3 columns
        </button>
      </nav>
      {tls && <TLSStrip tls={tls} />}
      {split ? (
        <div className="detail-body" style={colStyle(side.fraction)}>
          <div className="detail-cols" style={colStyle(cols.fraction)}>
            {request}
            <Splitter orientation="vertical" split={cols} label="Resize request and response" />
            <div className="detail-col">
              <header>Response {responseMeta}</header>
              {view && <Message m={view.response} tab={tab} />}
            </div>
          </div>
          <Splitter orientation="vertical" split={side} label="Resize inspector" />
          {inspector}
        </div>
      ) : (
        <div className="detail-body">
          <div className="detail-cols" style={colStyle(cols.fraction)}>
            {request}
            <Splitter orientation="vertical" split={cols} label="Resize request and response" />
            {grouped}
          </div>
        </div>
      )}
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

/**
 * TLS client facts for HTTPS rows: the JA4 fingerprint of the ClientHello,
 * and whether the tunnel was passed through raw (and why).
 */
function TLSStrip({ tls }: { tls: ExchangeTLSState }) {
  if (!tls.ja4 && !tls.tunnel && !tls.pinSuspected) return null
  return (
    <div className="detail-tls">
      {tls.ja4 && (
        <span title="JA4 TLS client fingerprint (FoxIO). Compare it with the User-Agent: a mismatch means the client is not what it claims.">
          JA4 <code className="mono">{tls.ja4}</code>
        </span>
      )}
      {tls.tunnel && <span className="badge badge-tunnel">tunnelled raw: {tls.tunnel}</span>}
      {tls.pinSuspected && <span className="badge badge-pin">pinning suspected: the client rejected Sluice&apos;s certificate although the CA is trusted</span>}
    </div>
  )
}
