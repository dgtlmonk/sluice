import { memo, type ReactNode, useState } from 'react'
import { asStringList, useStored } from '../hooks/useStored'
import type { Flag, IndexedRow, Inspection, Protocol, ProtocolInfo, Row, Section, SectionId, SectionMatch } from '../inspect/inspect'
import { fromFirstHit, matches, type Matcher } from '../view/search'
import { Highlight } from './Highlight'

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
  /** The selected exchange's id: per-row state is reset when it changes. */
  exchangeId: number | null
  /** The parsed exchange (DetailPane parses it, as it also counts the search's matches). */
  result: Inspection | null
  /** result's sections after the search: only the matching rows while searching. */
  sections: readonly SectionMatch[]
  error: string | null
  /** True when shown as a tab panel (grouped layout), false beside the messages. */
  asTab: boolean
  /** The detail pane's search, to highlight hits. Null when there is no search. */
  matcher: Matcher | null
}

/**
 * Burp-style Inspector: the selected exchange broken into parameters,
 * cookies and headers, one collapsible section each. Read-only for History.
 *
 * SECURITY: every row is captured traffic (untrusted). It is rendered only as
 * React text children and title attributes, never as HTML.
 */
// Memo: the detail pane re-renders on every Enter in the search field; the
// Inspector's props do not change then, so it is skipped.
export const Inspector = memo(function Inspector({ exchangeId, result, sections, error, asTab, matcher }: Props) {
  const [openIds, setOpenIds] = useStored<string[]>('sluice.inspector.sections', [...DEFAULT_OPEN], asStringList)
  const [raw, setRaw] = useState(false)

  const toggle = (id: SectionId) => setOpenIds(openIds.includes(id) ? openIds.filter((x) => x !== id) : [...openIds, id])

  return (
    <div id="detail-panel-inspector" role={asTab ? 'tabpanel' : 'region'} className="inspector" aria-label="Inspector">
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
      </header>
      {/* Keyed by exchange so per-row expand state and row paging never carry over to another one. */}
      <div className="insp-scroll" key={exchangeId ?? 'none'}>
        {error && <div className="insp-note detail-error">error: {error}</div>}
        {!error && !result && <div className="insp-note muted">Loading…</div>}
        {result &&
          sections.map(({ section: s, rows, protocol }) => (
            <InspectorSection
              key={s.id}
              section={s}
              rows={rows}
              matcher={matcher}
              open={openIds.includes(s.id)}
              onToggle={() => toggle(s.id)}
              raw={raw}
            >
              {protocol && <ProtocolRow info={result.protocol} matcher={matcher} />}
            </InspectorSection>
          ))}
      </div>
    </div>
  )
})

type SectionProps = {
  section: Section
  /** The rows to show: all of them, or those matching the search. */
  rows: readonly IndexedRow[]
  matcher: Matcher | null
  open: boolean
  onToggle: () => void
  raw: boolean
  children?: ReactNode
}

function InspectorSection({ section, rows, matcher, open, onToggle, raw, children }: SectionProps) {
  const [limit, setLimit] = useState(ROW_PAGE)
  const headId = `insp-${section.id}-head`
  const bodyId = `insp-${section.id}-body`
  const extra = section.id === 'attributes' ? 1 : 0 // + Protocol
  const count = section.rows.length + extra
  const found = rows.length + (children ? extra : 0)
  const searching = matcher !== null
  const hidden = rows.length - limit
  const countText = searching ? `${found}/${count}` : String(count)
  const countSpoken = searching ? `${found} of ${count} ${count === 1 ? 'item' : 'items'} match` : `${count} ${count === 1 ? 'item' : 'items'}`
  return (
    <section className={`insp-section${open ? ' open' : ''}${searching && found === 0 ? ' nomatch' : ''}`}>
      <h3>
        {/* aria-controls only while the body exists: it must point at a mounted element. */}
        <button id={headId} className="insp-toggle" aria-expanded={open} aria-controls={open ? bodyId : undefined} onClick={onToggle}>
          <span className="insp-chevron" aria-hidden="true">
            ▸
          </span>
          <span className="insp-section-title">{section.title}</span>
          <span className="insp-count" aria-hidden="true">
            {countText}
          </span>
          <span className="sr-only">, {countSpoken}</span>
        </button>
      </h3>
      {open && (
        <div id={bodyId} role="region" aria-labelledby={headId} className="insp-body">
          {section.note && <div className="insp-note">{section.note}</div>}
          {(rows.length > 0 || children) && (
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
                {rows.slice(0, limit).map(([i, r]) => (
                  <InspectorRow key={i} row={r} raw={raw} matcher={matcher} />
                ))}
              </tbody>
            </table>
          )}
          {hidden > 0 && (
            <div className="insp-more">
              <span className="muted">
                Showing {limit.toLocaleString()} of {rows.length.toLocaleString()}.
              </span>
              <button onClick={() => setLimit(limit + ROW_PAGE)}>Show {Math.min(hidden, ROW_PAGE).toLocaleString()} more</button>
            </div>
          )}
          {count === 0 && !section.note && <div className="insp-note muted">None.</div>}
          {searching && count > 0 && found === 0 && <div className="insp-note muted">No matches.</div>}
        </div>
      )}
    </section>
  )
}

/** Which HTTP version the exchange used, as Burp's HTTP/1 | HTTP/2 pill. */
function ProtocolRow({ info, matcher }: { info: ProtocolInfo; matcher: Matcher | null }) {
  return (
    <tr>
      <th scope="row">
        <Highlight text="Protocol" matcher={matcher} />
      </th>
      <td>
        <span className="insp-pills" role="group" aria-label={`Protocol: ${info.used}`}>
          {PROTOCOLS.map((p) => (
            <span key={p} className={`insp-pill${p === info.used ? ' on' : ''}`} aria-hidden="true">
              {p}
            </span>
          ))}
          {info.used === 'unknown' && <span className="muted">unknown</span>}
        </span>
        <div className="insp-detail">
          <Highlight text={info.note} matcher={matcher} />
        </div>
        {info.flag && <Flags flags={[info.flag]} />}
      </td>
    </tr>
  )
}

function InspectorRow({ row, raw, matcher }: { row: Row; raw: boolean; matcher: Matcher | null }) {
  const [expanded, setExpanded] = useState(false)
  const name = raw ? row.rawName : row.name
  const shown = raw ? row.raw : row.value
  const other = raw ? row.value : row.raw
  const long = isLong(shown)
  const title = other !== shown ? `${raw ? 'decoded' : 'raw'}: ${clip(other)}` : clip(shown)
  // A collapsed long text is cut at the cell edge: show it from its first
  // hit, so the highlight is not lost past the ellipsis.
  const nameText = isLong(name) && matcher ? fromFirstHit(name, matcher) : name
  const valueText = long && !expanded && matcher ? fromFirstHit(shown, matcher) : shown
  // The search also matches the form the Raw values toggle hides; without
  // this note such a row would look like a false hit.
  const hiddenHit = matcher !== null && !matches(name, matcher) && !matches(shown, matcher) && !(row.detail !== undefined && matches(row.detail, matcher))
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
            {name ? <Highlight text={nameText} matcher={matcher} /> : <span className="muted">(no name)</span>}
          </span>
          {row.dupe && <DupeBadge flag={row.dupe} count={row.dupes} />}
        </div>
      </th>
      <td>
        <div className="insp-value">
          <span className="insp-text" title={title} onClick={long ? toggle : undefined}>
            {shown === '' ? <span className="muted">(empty)</span> : <Highlight text={valueText} matcher={matcher} />}
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
        {row.detail && (
          <div className="insp-detail">
            <Highlight text={row.detail} matcher={matcher} />
          </div>
        )}
        {hiddenHit && <div className="insp-detail">Matches {raw ? 'the decoded form (turn off Raw values)' : 'as captured (turn on Raw values)'}</div>}
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

const isLong = (s: string) => s.length > LONG_VALUE || s.includes('\n')
