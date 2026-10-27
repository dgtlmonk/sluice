import { type KeyboardEvent, memo, type RefObject, useEffect, useMemo, useRef, useState } from 'react'
import { ExchangeDetail, ExchangeTLS, type ExchangeTLSState, type ExchangeView, type MessageView } from '../bridge'
import { useStored } from '../hooks/useStored'
import { inspect, matchedRows, searchInspection, type ExchangeContext, type SectionMatch } from '../inspect/inspect'
import { useExchangeStore } from '../store/exchanges'
import { findAll, HIGHLIGHT_CAP, makeMatcher, matches, type Found, type Matcher } from '../view/search'
import { statusText } from '../view/status'
import { Highlight, Marked } from './Highlight'
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
/** Typing updates the field at once; the (possibly large) bodies are searched once typing pauses. */
const SEARCH_DEBOUNCE_MS = 150
/** Raw-view matches of one message: head first, then body, sharing one highlight cap. */
type RawHits = { readonly head: Found; readonly body: Found; readonly shown: number; readonly total: number }
/**
 * The Raw view's current match, tied to the search and exchange it was moved
 * in: another query or exchange starts again at the first match, with no
 * effect (and no render with a stale cursor) needed to reset it.
 */
type Cursor = { readonly matcher: Matcher | null; readonly view: ExchangeView | null; readonly index: number }
/** The count beside the search field; `title` explains a capped count. */
type Count = { readonly text: string; readonly title?: string }

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
  const search = useDetailSearch()
  const { matcher } = search
  const [cursor, setCursor] = useState<Cursor>({ matcher: null, view: null, index: 0 })

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

  const view = loaded && 'view' in loaded ? loaded.view : null
  // Parsed here, not in the Inspector, so the search count can include its rows.
  // A fixed "now" per exchange keeps the parse pure and the memo stable.
  const inspection = useMemo(() => (view ? inspect(view.request, view.response, ctx, Date.now()) : null), [view, ctx])
  const sections = useMemo(() => (inspection ? searchInspection(inspection, matcher) : NO_SECTIONS), [inspection, matcher])
  const raw = useMemo(
    () => (matcher && view && tab === 'raw' ? { req: rawHits(view.request, matcher), res: rawHits(view.response, matcher) } : null),
    [matcher, view, tab],
  )
  const headerTotal = useMemo(
    () => (matcher && view && tab === 'headers' ? headerHits(view.request, matcher) + headerHits(view.response, matcher) : 0),
    [matcher, view, tab],
  )
  // Matches are numbered across both messages, request first.
  const reqShown = raw?.req.shown ?? 0
  const shown = reqShown + (raw?.res.shown ?? 0)
  const index = cursor.matcher === matcher && cursor.view === view ? cursor.index : 0
  const current = shown > 0 ? Math.min(index, shown - 1) : -1
  const split = layout === 'split'

  const sectionRef = useRef<HTMLElement>(null)
  useEffect(() => {
    if (current < 0) return
    sectionRef.current?.querySelector('mark.current')?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
  }, [current, raw, layout, right])

  if (!selected) {
    return <section className="detail detail-empty">Select a row to see its request and response.</section>
  }

  const tls = loaded && 'tls' in loaded ? loaded.tls : null
  const error = loaded && 'error' in loaded ? loaded.error : null

  /** Enter / Shift+Enter in the search field: next / previous match in the Raw view. */
  const step = (delta: 1 | -1) => {
    if (shown === 0) return
    // Grouped layout: the Inspector tab hides the response. If the current
    // match is in there, the first Enter only brings it forward; moving on
    // as well would skip it unseen.
    const responseHidden = !split && right === 'inspector'
    if (responseHidden && current >= reqShown) {
      setRight('response')
      return
    }
    const next = (current + delta + shown) % shown
    setCursor({ matcher, view, index: next })
    if (responseHidden && next >= reqShown) setRight('response')
  }
  const messagesCount = tab === 'raw' ? rawCount(raw, current, shown) : headersCount(headerTotal)
  const count = !matcher || !view ? null : searchCount(messagesCount, matchedRows(sections))
  /** The current match as an index into one message's own matches; -1 when it is in the other one. */
  const localCurrent = (first: number, hits: RawHits | null) => (hits && current >= first && current < first + hits.shown ? current - first : -1)
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
      {view && <Message m={view.request} tab={tab} matcher={matcher} hits={raw?.req ?? null} current={localCurrent(0, raw?.req ?? null)} />}
    </div>
  )
  const responseMessage = view && (
    <Message m={view.response} tab={tab} matcher={matcher} hits={raw?.res ?? null} current={localCurrent(reqShown, raw?.res ?? null)} />
  )
  const inspector = (
    <Inspector exchangeId={view?.id ?? null} result={inspection} sections={sections} error={error} asTab={!split} matcher={matcher} />
  )

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
        {responseMessage}
      </div>
    </div>
  )

  return (
    <section className="detail detail-tabbed" ref={sectionRef}>
      <nav className="detail-tabs">
        <div className="detail-tablist" role="tablist" aria-label="Message view">
          {(['raw', 'headers'] as const).map((t) => (
            <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
              {t === 'raw' ? 'Raw' : 'Headers'}
            </button>
          ))}
        </div>
        <SearchField query={search.query} onQuery={search.setQuery} inputRef={search.inputRef} count={count} onStep={step} />
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
              {responseMessage}
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

/**
 * The detail pane's search query. Kept while the selection changes (like
 * Burp), never stored: it is gone after a restart. What is being typed lives
 * in SearchField; this is the query after the debounce.
 */
function useDetailSearch() {
  const [query, setQuery] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  // Cmd+F already belongs to the History filter (FilterBar), so the detail
  // search takes Cmd+Shift+F (Ctrl+Shift+F off macOS). The field only exists
  // while a row is selected; with none, the key does nothing.
  useEffect(() => {
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      const find = (e.metaKey || e.ctrlKey) && e.shiftKey && !e.altKey && e.key.toLowerCase() === 'f'
      if (!find || !inputRef.current) return
      e.preventDefault()
      inputRef.current.focus()
      inputRef.current.select()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const matcher = useMemo(() => makeMatcher(query), [query])
  return { query, setQuery, matcher, inputRef }
}

type SearchFieldProps = {
  /** The query in effect (after the debounce). */
  query: string
  onQuery: (query: string) => void
  inputRef: RefObject<HTMLInputElement>
  count: Count | null
  onStep: (delta: 1 | -1) => void
}

function SearchField({ query, onQuery, inputRef, count, onStep }: SearchFieldProps) {
  // The draft is local: a keystroke re-renders only this field, never the
  // (possibly huge) messages. It starts from the query, which outlives the
  // field when no row is selected.
  const [draft, setDraft] = useState(query)

  useEffect(() => {
    if (draft === query) return
    const timer = window.setTimeout(() => onQuery(draft), SEARCH_DEBOUNCE_MS)
    return () => window.clearTimeout(timer)
  }, [draft, query, onQuery])

  const clear = () => {
    setDraft('')
    onQuery('') // no debounce: clearing should feel instant
  }
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    // Enter or Escape that ends an IME composition (Japanese, Chinese, ...) belongs to the IME.
    // WebKit reports isComposing=false on the Enter that commits IME text; keyCode 229 catches it.
    if (e.nativeEvent.isComposing || e.keyCode === 229) return
    if (e.key === 'Escape') {
      e.preventDefault()
      clear()
      e.currentTarget.blur()
      return
    }
    if (e.key !== 'Enter') return
    e.preventDefault()
    // Enter before the debounce fires searches now; the next Enter steps.
    if (draft !== query) onQuery(draft)
    else onStep(e.shiftKey ? -1 : 1)
  }
  return (
    <div className="detail-search">
      <div className="detail-search-input">
        <svg className="detail-search-icon" viewBox="0 0 16 16" aria-hidden="true">
          <circle cx="7" cy="7" r="4.5" />
          <path d="M10.5 10.5 14 14" />
        </svg>
        <input
          ref={inputRef}
          type="text"
          value={draft}
          aria-label="Search request, response and inspector"
          aria-keyshortcuts="Meta+Shift+F Control+Shift+F"
          aria-describedby="detail-search-count"
          title="Search (Shift+Cmd+F). Raw view: Enter next match, Shift+Enter previous. Esc clears."
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          autoComplete="off"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKeyDown}
        />
        {draft !== '' && (
          <button
            className="filter-clear"
            title="Clear search (Esc)"
            aria-label="Clear search"
            onClick={() => {
              clear()
              inputRef.current?.focus()
            }}
          >
            ✕
          </button>
        )}
      </div>
      <span id="detail-search-count" className="detail-search-count" aria-live="polite" title={count?.title}>
        {count?.text}
      </span>
    </div>
  )
}

function rawHits(m: MessageView, matcher: Matcher): RawHits {
  if (!m.captured) return { head: NO_HITS, body: NO_HITS, shown: 0, total: 0 }
  const head = findAll(m.head, matcher)
  const body = findAll(m.body, matcher, HIGHLIGHT_CAP - head.ranges.length)
  return { head, body, shown: head.ranges.length + body.ranges.length, total: head.total + body.total }
}
const NO_HITS: Found = { ranges: [], total: 0 }
const NO_SECTIONS: readonly SectionMatch[] = []

/** Matches the Headers view shows: start line, names and values of every header. */
function headerHits(m: MessageView, matcher: Matcher): number {
  if (!m.captured) return 0
  const count = (s: string) => findAll(s, matcher, 0).total
  return m.headers.reduce((n, h) => n + (h.malformed ? 0 : count(h.name)) + count(h.value), count(m.startLine))
}

/** Raw view: which match is current, of how many. Null for none. */
function rawCount(raw: { req: RawHits; res: RawHits } | null, current: number, shown: number): Count | null {
  const total = (raw?.req.total ?? 0) + (raw?.res.total ?? 0)
  if (total === 0) return null
  if (shown === total) return { text: `${(current + 1).toLocaleString()} of ${total.toLocaleString()}` }
  return {
    text: `${(current + 1).toLocaleString()} of ${shown.toLocaleString()}+`,
    title: `${total.toLocaleString()} matches; only the first ${HIGHLIGHT_CAP.toLocaleString()} in each message are highlighted.`,
  }
}

/** Headers view: how many matches. Null for none. */
function headersCount(total: number): Count | null {
  if (total === 0) return null
  return { text: total === 1 ? '1 match' : `${total.toLocaleString()} matches` }
}

/** The messages' count, then the Inspector rows the search leaves; "No matches" only when both are empty. */
function searchCount(messages: Count | null, rows: number): Count {
  if (rows === 0) return messages ?? { text: 'No matches' }
  const inspector = `${rows.toLocaleString()} in Inspector`
  const why = rows === 1 ? '1 Inspector row matches.' : `${rows.toLocaleString()} Inspector rows match.`
  if (!messages) return { text: inspector, title: why }
  return { text: `${messages.text} · ${inspector}`, title: messages.title ? `${messages.title} ${why}` : why }
}

type MessageProps = {
  m: MessageView
  tab: Tab
  matcher: Matcher | null
  /** Raw-view matches; null when there is no search (or in the Headers view). */
  hits: RawHits | null
  /** The current match as an index into `hits` (head, then body); -1 when it is not in this message. */
  current: number
}

// Memo: Enter moves the current match; a message that neither held nor gets
// it keeps its props and is skipped.
const Message = memo(function Message({ m, tab, matcher, hits, current }: MessageProps) {
  if (!m.captured) return <pre className="muted">(not captured)</pre>
  return tab === 'raw' ? <RawView m={m} hits={hits} current={current} /> : <HeaderTable m={m} matcher={matcher} />
})

function RawView({ m, hits, current }: { m: MessageView; hits: RawHits | null; current: number }) {
  const head = hits?.head.ranges ?? NO_HITS.ranges
  return (
    <div className="detail-scroll">
      <BodyNotice m={m} />
      <pre>
        <Marked text={m.head} ranges={head} current={current < head.length ? current : -1} />
        {m.bodyEncoding === 'hex' && m.bodyShown > 0 && <span className="muted">(binary body, hex view){'\n'}</span>}
        <Marked text={m.body} ranges={hits?.body.ranges ?? NO_HITS.ranges} current={current >= head.length ? current - head.length : -1} />
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

function HeaderTable({ m, matcher }: { m: MessageView; matcher: Matcher | null }) {
  // Index kept with each row: duplicates are legal, so the index is the key.
  const rows = useMemo(
    () =>
      m.headers
        .map((h, i) => ({ h, i }))
        .filter(({ h }) => !matcher || (!h.malformed && matches(h.name, matcher)) || matches(h.value, matcher)),
    [m, matcher],
  )
  return (
    <div className="detail-scroll">
      <div className="detail-startline">
        <Highlight text={m.startLine} matcher={matcher} />
      </div>
      <table className="header-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {/* Index keys: duplicates are legal and kept in wire order. */}
          {rows.map(({ h, i }) => (
            <tr key={i} className={h.malformed ? 'malformed' : undefined}>
              <td>{h.malformed ? '(malformed line)' : <Highlight text={h.name} matcher={matcher} />}</td>
              <td>
                <Highlight text={h.value} matcher={matcher} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {matcher && rows.length === 0 && m.headers.length > 0 && <div className="insp-note muted">No matching headers.</div>}
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
