import { type KeyboardEvent, type PointerEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  columnSizingFeature,
  createColumnHelper,
  functionalUpdate,
  tableFeatures,
  useTable,
  type ColumnSizingState,
  type Updater,
} from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useExchangeStore, type Exchange } from '../store/exchanges'
import { rowHeightFor, usePrefsStore } from '../store/prefs'
import { statusText } from '../view/status'
import { indexInView, positionAt } from '../view/rowView'
import { followsArrival, type SortColumn } from '../view/sort'

const OVERSCAN = 20

const features = tableFeatures({ columnSizingFeature })
const helper = createColumnHelper<typeof features, Exchange>()

const columns = helper.columns([
  helper.accessor('id', { header: '#', size: 84, minSize: 40 }),
  helper.accessor('method', { header: 'Method', size: 72, minSize: 48 }),
  helper.accessor((x) => hostLabel(x), { id: 'host', header: 'Host', size: 260, minSize: 80 }),
  helper.accessor('path', { header: 'Path', size: 320, minSize: 80 }),
  helper.accessor('status', {
    header: 'Status',
    size: 64,
    minSize: 44,
    cell: (info) => <span className={statusClass(info.getValue())}>{statusText(info.getValue())}</span>,
  }),
  helper.accessor('respSize', { header: 'Length', size: 84, minSize: 48, cell: (info) => info.getValue().toLocaleString() }),
  helper.accessor('mime', { header: 'MIME', size: 150, minSize: 60 }),
  helper.accessor('startedAt', { header: 'Time', size: 108, minSize: 60, cell: (info) => clock(info.getValue()) }),
  helper.accessor('isLLM', {
    header: 'LLM',
    size: 52,
    minSize: 36,
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

// Column widths are remembered per viewer in localStorage, like the pane splits
// (Splitter.tsx): a convenience only, so any failure falls back to the defaults.
const WIDTHS_KEY = 'sluice.columns.history'
const MIN_WIDTH = 36 // fallback floor for a column without its own minSize
const MAX_WIDTH = 2000
const KEY_STEP = 8 // px per arrow key on a focused resize handle
const COLUMN_IDS = new Set<string>(columns.map((c) => c.id ?? ('accessorKey' in c ? String(c.accessorKey) : '')))

function readWidths(): ColumnSizingState {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(WIDTHS_KEY) ?? '{}')
    if (typeof parsed !== 'object' || parsed === null) return {}
    // Keep only known columns with sane widths; TanStack clamps to minSize.
    return Object.fromEntries(
      Object.entries(parsed).filter(([id, w]) => COLUMN_IDS.has(id) && typeof w === 'number' && w > 0 && w <= MAX_WIDTH),
    )
  } catch {
    return {}
  }
}

function writeWidths(widths: ColumnSizingState) {
  try {
    localStorage.setItem(WIDTHS_KEY, JSON.stringify(widths))
  } catch {
    // storage blocked: the widths still apply for this session
  }
}

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

  // Rows are fixed-height (virtualized, never measured), so the height must
  // follow the font size; re-measure whenever it changes.
  const rowHeight = usePrefsStore((s) => rowHeightFor(s.prefs.fontSize))
  const scrollRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: viewCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: OVERSCAN,
  })
  useEffect(() => virtualizer.measure(), [virtualizer, rowHeight])

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

  // Widths are held here (not in table-internal state) so they can be seeded from
  // and saved to storage. Drags update widths live; storage is written once, on drop.
  const [columnSizing, setColumnSizing] = useState(readWidths)
  const dragging = useRef(false)
  const latestSizing = useRef(columnSizing)
  const onColumnSizingChange = useCallback((updater: Updater<ColumnSizingState>) => {
    const next = functionalUpdate(updater, latestSizing.current)
    latestSizing.current = next
    setColumnSizing(next)
    if (!dragging.current) writeWidths(next) // e.g. a double-click reset
  }, [])

  const table = useTable({
    features,
    columns,
    data: windowData,
    getRowId: (x) => String(x.id),
    state: { columnSizing },
    onColumnSizingChange,
  })
  const tableRows = table.getRowModel().rows

  // One CSS variable per column, recomputed only when widths change. Header and
  // body cells both read var(--col-<id>), so they cannot drift apart, and a drag
  // changes one style object instead of every cell's inline width.
  const columnVars = useMemo(() => {
    const vars: Record<string, string> = {}
    for (const column of table.getAllLeafColumns()) vars[`--col-${column.id}`] = `${column.getSize()}px`
    return vars as React.CSSProperties
    // columnSizing is what getSize() reads; the table identity is stable.
  }, [table, columnSizing])

  // Column being dragged, for the handle's highlight.
  const [resizing, setResizing] = useState<string | null>(null)
  const suppressClick = useRef(false)
  const endDrag = useRef<(() => void) | null>(null)
  useEffect(() => () => endDrag.current?.(), [])

  const resizeColumn = (id: string, width: number, persist: boolean) => {
    const column = table.getColumn(id)
    if (!column) return
    const min = column.columnDef.minSize ?? MIN_WIDTH
    dragging.current = !persist
    table.setColumnSizing((old) => ({ ...old, [id]: Math.round(Math.min(MAX_WIDTH, Math.max(min, width))) }))
    dragging.current = false
  }

  // Same drag model as Splitter.tsx: pointer capture keeps move/up events on the
  // handle even outside the webview, so no document listeners can leak.
  const onResizePointerDown = (e: PointerEvent<HTMLDivElement>, id: string) => {
    if (e.button !== 0) return
    const target = e.currentTarget
    e.stopPropagation()
    e.preventDefault() // no text selection while dragging
    target.focus() // preventDefault skips the focus a click would give
    target.setPointerCapture(e.pointerId)
    const startX = e.clientX
    const startWidth = table.getColumn(id)?.getSize() ?? 0
    let last = startWidth
    setResizing(id)
    const move = (ev: globalThis.PointerEvent) => {
      last = startWidth + ev.clientX - startX
      resizeColumn(id, last, false)
    }
    const end = () => {
      target.removeEventListener('pointermove', move)
      for (const t of ['pointerup', 'pointercancel', 'lostpointercapture'] as const) target.removeEventListener(t, end)
      document.body.classList.remove('resizing', 'resizing-col')
      endDrag.current = null
      setResizing(null)
      // The click that ends this drag would toggle sort; ignore only that one.
      suppressClick.current = true
      setTimeout(() => (suppressClick.current = false), 0)
      resizeColumn(id, last, true) // persist once, when the drag settles
    }
    target.addEventListener('pointermove', move)
    for (const t of ['pointerup', 'pointercancel', 'lostpointercapture'] as const) target.addEventListener(t, end)
    document.body.classList.add('resizing', 'resizing-col')
    endDrag.current = end
  }

  const onResizeKeyDown = (e: KeyboardEvent<HTMLDivElement>, id: string) => {
    const column = table.getColumn(id)
    if (!column) return
    if (e.key === 'ArrowLeft') resizeColumn(id, column.getSize() - KEY_STEP, true)
    else if (e.key === 'ArrowRight') resizeColumn(id, column.getSize() + KEY_STEP, true)
    else if (e.key === 'Home') column.resetSize()
    else return
    e.preventDefault()
    e.stopPropagation()
  }

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
    <div className="grid" style={columnVars}>
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
              style={cellStyle(id)}
              onClick={() => {
                if (!suppressClick.current) toggleSort(id)
              }}
            >
              <table.FlexRender header={header} />
              {dir && <span className="sort-arrow">{dir === 'asc' ? '\u25B2' : '\u25BC'}</span>}
              <div
                className={'col-resizer' + (resizing === id ? ' active' : '')}
                role="separator"
                aria-orientation="vertical"
                aria-label={`Resize ${String(header.column.columnDef.header)} column`}
                aria-valuenow={Math.round(header.column.getSize())}
                aria-valuemin={header.column.columnDef.minSize ?? MIN_WIDTH}
                aria-valuemax={MAX_WIDTH}
                title="Drag to resize; double-click to reset"
                tabIndex={0}
                onPointerDown={(e) => onResizePointerDown(e, id)}
                onKeyDown={(e) => onResizeKeyDown(e, id)}
                onClick={(e) => e.stopPropagation()}
                onDoubleClick={(e) => {
                  e.stopPropagation()
                  header.column.resetSize()
                }}
              />
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
                style={{ transform: `translateY(${item.start}px)`, height: rowHeight }}
                onMouseDown={() => select(pos)}
              >
                {row.getAllCells().map((cell) => (
                  <div
                    key={cell.id}
                    role="cell"
                    className={cellClass(cell.column.id)}
                    style={cellStyle(cell.column.id)}
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

// Widths come from the per-column CSS variables set on .grid (see columnVars).
function cellStyle(columnId: string): React.CSSProperties {
  const width = `var(--col-${columnId})`
  return columnId === GROW_COLUMN ? { flex: `1 1 ${width}` } : { flex: `0 0 ${width}` }
}

function hostLabel(x: Exchange): string {
  const defaultPort = (x.scheme === 'https' && x.port === 443) || (x.scheme === 'http' && x.port === 80)
  return defaultPort ? `${x.scheme}://${x.host}` : `${x.scheme}://${x.host}:${x.port}`
}

function statusClass(status: number): string {
  if (status === 0) return 'status s0' // no response sent (e.g. an unused CONNECT)
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
