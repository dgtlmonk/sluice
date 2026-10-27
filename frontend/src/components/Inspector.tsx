import { type ReactNode, useMemo, useState } from 'react'
import type { ExchangeView } from '../bridge'
import { asStringList, useStored } from '../hooks/useStored'
import { inspect, type ExchangeContext, type Flag, type Protocol, type ProtocolInfo, type Row, type Section, type SectionId } from '../inspect/inspect'

/** Sections open the first time; after that the viewer's choice is remembered. */
const DEFAULT_OPEN: readonly SectionId[] = ['attributes', 'query', 'body', 'reqCookies', 'resCookies']
const PROTOCOLS: readonly Protocol[] = ['HTTP/1', 'HTTP/2']
/** Values longer than this (or with a line break) get an expand control. */
const LONG_VALUE = 40
/** Hover titles are capped: a 256 KiB value in a tooltip helps no one. */
const TITLE_MAX = 2000
/**
 * Rows rendered per section before a "Show more" button. A hostile request
 * can carry 20,000 parameters; rendering them all at once freezes the pane.
 */
const ROW_PAGE = 500

type Props = {
  view: ExchangeView | null
  ctx: ExchangeContext
  error: string | null
  onClose: () => void
}

/**
 * Burp-style Inspector: the selected exchange broken into parameters,
 * cookies and headers, one collapsible section each. Read-only for History.
 *
 * SECURITY: every row is captured traffic (untrusted). It is rendered only as
 * React text children and title attributes, never as HTML.
 */
export function Inspector({ view, ctx, error, onClose }: Props) {
  const [openIds, setOpenIds] = useStored<string[]>('sluice.inspector.sections', [...DEFAULT_OPEN], asStringList)
  const [raw, setRaw] = useState(false)
  // A fixed "now" per exchange keeps the parse pure and the memo stable.
  const result = useMemo(() => (view ? inspect(view.request, view.response, ctx, Date.now()) : null), [view, ctx])

  const toggle = (id: SectionId) => setOpenIds(openIds.includes(id) ? openIds.filter((x) => x !== id) : [...openIds, id])

  return (
    <aside id="inspector" className="inspector" aria-label="Inspector">
      <header className="insp-head">
        <span className="insp-title">Inspector</span>
        <button
          className={raw ? 'active' : ''}
          aria-pressed={raw}
          title="Show names and values as captured instead of URL- and JSON-decoded"
          onClick={() => setRaw(!raw)}
        >
          Raw values
        </button>
        <button className="insp-close" aria-label="Close inspector" title="Close inspector" onClick={onClose}>
          ×
        </button>
      </header>
      {/* Keyed by exchange so per-row expand state and row paging never carry over to another one. */}
      <div className="insp-scroll" key={view?.id ?? 'none'}>
        {error && <div className="insp-note detail-error">error: {error}</div>}
        {!error && !result && <div className="insp-note muted">Loading…</div>}
        {result?.sections.map((s) => (
          <InspectorSection key={s.id} section={s} open={openIds.includes(s.id)} onToggle={() => toggle(s.id)} raw={raw}>
            {s.id === 'attributes' && <ProtocolRow info={result.protocol} />}
          </InspectorSection>
        ))}
      </div>
    </aside>
  )
}

type SectionProps = {
  section: Section
  open: boolean
  onToggle: () => void
  raw: boolean
  children?: ReactNode
}

function InspectorSection({ section, open, onToggle, raw, children }: SectionProps) {
  const [limit, setLimit] = useState(ROW_PAGE)
  const headId = `insp-${section.id}-head`
  const bodyId = `insp-${section.id}-body`
  const count = section.rows.length + (section.id === 'attributes' ? 1 : 0) // + Protocol
  const hidden = section.rows.length - limit
  return (
    <section className={`insp-section${open ? ' open' : ''}`}>
      <h3>
        {/* aria-controls only while the body exists: it must point at a mounted element. */}
        <button id={headId} className="insp-toggle" aria-expanded={open} aria-controls={open ? bodyId : undefined} onClick={onToggle}>
          <span className="insp-chevron" aria-hidden="true">
            ▸
          </span>
          <span className="insp-section-title">{section.title}</span>
          <span className="insp-count" aria-hidden="true">
            {count}
          </span>
          <span className="sr-only">
            , {count} {count === 1 ? 'item' : 'items'}
          </span>
        </button>
      </h3>
      {open && (
        <div id={bodyId} role="region" aria-labelledby={headId} className="insp-body">
          {section.note && <div className="insp-note">{section.note}</div>}
          {(section.rows.length > 0 || children) && (
            <table className="insp-table">
              <thead className="sr-only">
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Value</th>
                </tr>
              </thead>
              <tbody>
                {children}
                {/* Index keys: duplicate names are kept, in wire order. */}
                {section.rows.slice(0, limit).map((r, i) => (
                  <InspectorRow key={i} row={r} raw={raw} />
                ))}
              </tbody>
            </table>
          )}
          {hidden > 0 && (
            <div className="insp-more">
              <span className="muted">
                Showing {limit.toLocaleString()} of {section.rows.length.toLocaleString()}.
              </span>
              <button onClick={() => setLimit(limit + ROW_PAGE)}>Show {Math.min(hidden, ROW_PAGE).toLocaleString()} more</button>
            </div>
          )}
          {section.rows.length === 0 && !section.note && !children && <div className="insp-note muted">None.</div>}
        </div>
      )}
    </section>
  )
}

/** Which HTTP version the exchange used, as Burp's HTTP/1 | HTTP/2 pill. */
function ProtocolRow({ info }: { info: ProtocolInfo }) {
  return (
    <tr>
      <th scope="row">Protocol</th>
      <td>
        <span className="insp-pills" role="group" aria-label={`Protocol: ${info.used}`}>
          {PROTOCOLS.map((p) => (
            <span key={p} className={`insp-pill${p === info.used ? ' on' : ''}`} aria-hidden="true">
              {p}
            </span>
          ))}
          {info.used === 'unknown' && <span className="muted">unknown</span>}
        </span>
        <div className="insp-detail">{info.note}</div>
        {info.flag && <Flags flags={[info.flag]} />}
      </td>
    </tr>
  )
}

function InspectorRow({ row, raw }: { row: Row; raw: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const name = raw ? row.rawName : row.name
  const shown = raw ? row.raw : row.value
  const other = raw ? row.value : row.raw
  const long = shown.length > LONG_VALUE || shown.includes('\n')
  const title = other !== shown ? `${raw ? 'decoded' : 'raw'}: ${clip(other)}` : clip(shown)
  const toggle = () => {
    // A click that ends a text selection is a copy, not a toggle.
    if (window.getSelection()?.toString()) return
    setExpanded(!expanded)
  }
  return (
    <tr className={expanded ? 'expanded' : undefined}>
      <th scope="row">
        <div className="insp-name">
          <span className="insp-name-text" title={clip(name)}>
            {name || <span className="muted">(no name)</span>}
          </span>
          {row.dupe && <DupeBadge flag={row.dupe} count={row.dupes} />}
        </div>
      </th>
      <td>
        <div className="insp-value">
          <span className="insp-text" title={title} onClick={long ? toggle : undefined}>
            {shown === '' ? <span className="muted">(empty)</span> : shown}
          </span>
          {long && (
            <button
              className="insp-expand"
              aria-expanded={expanded}
              aria-label={`${expanded ? 'Collapse' : 'Expand'} value of ${name || 'unnamed row'}`}
              onClick={() => setExpanded(!expanded)}
            >
              <span aria-hidden="true">{expanded ? '−' : '+'}</span>
            </button>
          )}
        </div>
        {row.detail && <div className="insp-detail">{row.detail}</div>}
        {row.flags.length > 0 && <Flags flags={row.flags} />}
      </td>
    </tr>
  )
}

/** "×2" next to a repeated name; screen readers get the count and why it matters. */
function DupeBadge({ flag, count }: { flag: Flag; count: number }) {
  return (
    <span className={`insp-flag ${flag.tone}`} title={flag.why}>
      <span aria-hidden="true">{flag.label}</span>
      <span className="sr-only">
        {' '}
        (repeated {count} times: {flag.why})
      </span>
    </span>
  )
}

function Flags({ flags }: { flags: readonly Flag[] }) {
  return (
    <div className="insp-flags">
      {flags.map((f) => (
        <span key={f.label} className={`insp-flag ${f.tone}`} title={f.why}>
          {f.label}
        </span>
      ))}
    </div>
  )
}

const clip = (s: string) => (s.length > TITLE_MAX ? `${s.slice(0, TITLE_MAX)}…` : s)
