import { useEffect, useMemo, useRef } from 'react'
import { columnSizingFeature, createColumnHelper, tableFeatures, useTable } from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useExchangeStore, type Exchange } from '../store/exchanges'
import { indexInView, positionAt } from '../view/rowView'
import { followsArrival, type SortColumn } from '../view/sort'

const ROW_HEIGHT = 22
const OVERSCAN = 20

const features = tableFeatures({ columnSizingFeature })
const helper = createColumnHelper<typeof features, Exchange>()

const columns = helper.columns([
  helper.accessor('id', { header: '#', size: 84 }),
  helper.accessor('method', { header: 'Method', size: 72 }),
  helper.accessor((x) => hostLabel(x), { id: 'host', header: 'Host', size: 260 }),
  helper.accessor('path', { header: 'Path', size: 320 }),
  helper.accessor('status', {
    header: 'Status',
    size: 64,
    cell: (info) => <span className={statusClass(info.getValue())}>{info.getValue()}</span>,
  }),
  helper.accessor('respSize', { header: 'Length', size: 84, cell: (info) => info.getValue().toLocaleString() }),
  helper.accessor('mime', { header: 'MIME', size: 150 }),
  helper.accessor('startedAt', { header: 'Time', size: 108, cell: (info) => clock(info.getValue()) }),
  helper.accessor('isLLM', {
    header: 'LLM',
    size: 52,
    cell: (info) =>
      info.getValue() ? (
        <span className="llm-flag" title={llmTooltip(info.row.original.llmReason)}>
          LLM
        </span>
      ) : null,
  }),
])

// The path column absorbs spare width; the rest stay fixed.
const GROW_COLUMN = 'path'
const NUMERIC_COLUMNS = new Set(['id', 'status', 'respSize'])

/**
 * History grid. TanStack Virtual spans the whole view (filtered + sorted row
 * positions, see view/rowView.ts); TanStack Table only models the visible window.
 * That keeps per-update work proportional to the viewport rather than to 100k+
 * rows. Filtering and sorting run in the store, not in the table, matching the M2
 * plan to page rows from the engine with WHERE / ORDER BY.
 */
export function HistoryGrid() {
  const rows = useExchangeStore((s) => s.rows)
  const count = useExchangeStore((s) => s.count)
  const view = useExchangeStore((s) => s.view)
  const viewCount = useExchangeStore((s) => s.viewCount)
  const sort = useExchangeStore((s) => s.sort)
  const selectedPos = useExchangeStore((s) => s.selectedPos)
  const autoScroll = useExchangeStore((s) => s.autoScroll)
  const select = useExchangeStore((s) => s.select)
  const toggleSort = useExchangeStore((s) => s.toggleSort)
  const setAutoScroll = useExchangeStore((s) => s.setAutoScroll)

  // Following the tail only means something when new rows land at the bottom.
  const following = autoScroll && followsArrival(sort)

  const scrollRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: viewCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: OVERSCAN,
  })

  const items = virtualizer.getVirtualItems()
  const first = items.length > 0 ? items[0].index : 0
  const last = items.length > 0 ? items[items.length - 1].index : -1

  // A window's contents change when its bounds move, the view is rebuilt (new
  // identity), or a sorted view gains rows (inserted mid-view, so viewCount grows).
  const windowData = useMemo(() => {
    const out: Exchange[] = []
    for (let i = first; i <= last && i < viewCount; i++) out.push(rows[positionAt(view, i)])
    return out
  }, [rows, view, viewCount, first, last])

  const table = useTable({
    features,
    columns,
    data: windowData,
    getRowId: (x) => String(x.id),
  })
  const tableRows = table.getRowModel().rows

  useEffect(() => {
    if (!following || viewCount === 0) return
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [following, viewCount, view])

  // After a filter or sort change, bring the selected row back into sight (or go to
  // the top when nothing is selected): the old scroll offset points at unrelated rows.
  const shownView = useRef(view)
  useEffect(() => {
    if (shownView.current === view) return
    shownView.current = view
    if (following) return
    const { selectedPos: pos, count: rowCount } = useExchangeStore.getState()
    const index = pos === null ? -1 : indexInView(view, rowCount, pos)
    if (index >= 0) virtualizer.scrollToIndex(index, { align: 'center' })
    else virtualizer.scrollToOffset(0)
  }, [view, following, virtualizer])

  return (
    <div className="grid">
      <div className="grid-header" role="row">
        {table.getHeaderGroups()[0].headers.map((header) => {
          const id = header.column.id as SortColumn
          const dir = sort?.column === id ? sort.dir : null
          return (
            <div
              key={header.id}
              role="columnheader"
              aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none'}
              title="Sort: ascending, descending, off"
              className={cellClass(id) + ' sortable' + (dir ? ' sorted' : '')}
              style={cellStyle(id, header.column.getSize())}
              onClick={() => toggleSort(id)}
            >
              <table.FlexRender header={header} />
              {dir && <span className="sort-arrow">{dir === 'asc' ? '\u25B2' : '\u25BC'}</span>}
            </div>
          )
        })}
      </div>

      <div
        ref={scrollRef}
        className="grid-body"
        onWheel={(e) => {
          // Scrolling up means the user wants to read; stop yanking them to the bottom.
          if (following && e.deltaY < 0) setAutoScroll(false)
        }}
      >
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {items.map((item) => {
            const row = tableRows[item.index - first]
            if (!row) return null
            const pos = positionAt(view, item.index)
            return (
              <div
                key={row.id}
                role="row"
                className={'grid-row' + (pos === selectedPos ? ' selected' : '') + (item.index % 2 ? ' odd' : '')}
                style={{ transform: `translateY(${item.start}px)`, height: ROW_HEIGHT }}
                onMouseDown={() => select(pos)}
              >
                {row.getAllCells().map((cell) => (
                  <div
                    key={cell.id}
                    role="cell"
                    className={cellClass(cell.column.id)}
                    style={cellStyle(cell.column.id, cell.column.getSize())}
                  >
                    <table.FlexRender cell={cell} />
                  </div>
                ))}
              </div>
            )
          })}
        </div>
        {count === 0 && <div className="grid-empty">No exchanges yet. Seed rows or start the stream.</div>}
        {count > 0 && viewCount === 0 && <div className="grid-empty">No exchanges match the filter.</div>}
      </div>
    </div>
  )
}

function cellClass(columnId: string): string {
  return NUMERIC_COLUMNS.has(columnId) ? 'cell num' : 'cell'
}

function cellStyle(columnId: string, size: number): React.CSSProperties {
  return columnId === GROW_COLUMN ? { flex: `1 1 ${size}px` } : { flex: `0 0 ${size}px` }
}

function hostLabel(x: Exchange): string {
  const defaultPort = (x.scheme === 'https' && x.port === 443) || (x.scheme === 'http' && x.port === 80)
  return defaultPort ? `${x.scheme}://${x.host}` : `${x.scheme}://${x.host}:${x.port}`
}

function statusClass(status: number): string {
  if (status >= 500) return 'status s5'
  if (status >= 400) return 'status s4'
  if (status >= 300) return 'status s3'
  return 'status s2'
}

const pad2 = (n: number) => (n < 10 ? '0' : '') + n

function clock(unixMs: number): string {
  const d = new Date(unixMs)
  const ms = d.getMilliseconds()
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}.${ms < 10 ? '00' : ms < 100 ? '0' : ''}${ms}`
}

const LLM_RULES: Readonly<Record<string, string>> = {
  path: 'known LLM API path',
  json: 'chat/completion JSON request (model + messages/prompt)',
  sse: 'text/event-stream response',
}

/** Tooltip for the LLM badge: which detection rules matched (e.g. "path,sse"). */
function llmTooltip(reason: string | undefined): string {
  if (!reason) return 'LLM traffic'
  return 'LLM: ' + reason.split(',').map((r) => LLM_RULES[r] ?? r).join('; ')
}
