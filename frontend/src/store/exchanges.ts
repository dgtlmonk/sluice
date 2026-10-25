import { create } from 'zustand'
import type { synth } from '../../wailsjs/go/models'
import { NO_FILTER, parseQuery, type RowFilter } from '../filter/query'
import { buildView, extendView, type RowView } from '../view/rowView'
import { nextSort, type SortColumn, type SortState } from '../view/sort'

export type Exchange = synth.Exchange

type ExchangeState = {
  /**
   * Append-only row buffer, mutated in place for O(batch) appends.
   * Its identity changes only on clear(); subscribe to `count` to react to growth.
   */
  rows: Exchange[]
  count: number
  /** Total exchanges ever received; the status bar samples it for events/sec. */
  received: number

  /**
   * What the grid shows: positions into `rows`, filtered and sorted (null = all
   * rows in arrival order). Replaced on a filter/sort change, extended in place
   * per batch; subscribe to `viewCount` for growth and to `view` for rebuilds.
   */
  view: RowView
  viewCount: number

  /** Filter input text as typed; `query` is the debounced text the view is built from. */
  queryDraft: string
  query: string
  llmOnly: boolean
  filter: RowFilter
  sort: SortState | null

  selected: Exchange | null
  /** Position of `selected` in `rows`; positions are stable because rows are append-only. */
  selectedPos: number | null
  autoScroll: boolean
  lastError: string | null

  clear: () => void
  select: (pos: number | null) => void
  setQueryDraft: (text: string) => void
  applyQuery: (text: string) => void
  setLlmOnly: (on: boolean) => void
  toggleSort: (column: SortColumn) => void
  setAutoScroll: (on: boolean) => void
  setError: (message: string | null) => void
}

export const useExchangeStore = create<ExchangeState>()((set, get) => {
  /** Rebuilds the view for a new filter/sort and drops the selection if it got filtered out. */
  const rebuild = (patch: { query?: string; llmOnly?: boolean; sort?: SortState | null }): Partial<ExchangeState> => {
    const s = get()
    const query = patch.query ?? s.query
    const llmOnly = patch.llmOnly ?? s.llmOnly
    const sort = patch.sort === undefined ? s.sort : patch.sort
    const filter: RowFilter = query === s.query && llmOnly === s.llmOnly ? s.filter : { query: parseQuery(query), llmOnly }
    const view = buildView(s.rows, filter, sort)
    const viewCount = view === null ? s.rows.length : view.length

    // A sort keeps every row, so only a filter change can hide the selection.
    const hidden = s.selectedPos !== null && view !== null && filter !== s.filter && !view.includes(s.selectedPos)
    return {
      query,
      llmOnly,
      filter,
      sort,
      view,
      viewCount,
      ...(hidden ? { selected: null, selectedPos: null } : {}),
    }
  }

  return {
    rows: [],
    count: 0,
    received: 0,
    view: null,
    viewCount: 0,
    queryDraft: '',
    query: '',
    llmOnly: false,
    filter: NO_FILTER,
    sort: null,
    selected: null,
    selectedPos: null,
    autoScroll: false,
    lastError: null,

    clear: () => {
      pending.length = 0
      set({
        rows: [],
        count: 0,
        view: null,
        viewCount: 0,
        queryDraft: '',
        query: '',
        llmOnly: false,
        filter: NO_FILTER,
        sort: null,
        selected: null,
        selectedPos: null,
      })
    },
    select: (pos) => {
      const row = pos === null ? undefined : get().rows[pos]
      set(row ? { selected: row, selectedPos: pos } : { selected: null, selectedPos: null })
    },
    setQueryDraft: (text) => set({ queryDraft: text }),
    applyQuery: (text) => {
      if (text === get().query) return
      set(rebuild({ query: text }))
    },
    setLlmOnly: (on) => {
      if (on === get().llmOnly) return
      set(rebuild({ llmOnly: on }))
    },
    toggleSort: (column) => set(rebuild({ sort: nextSort(get().sort, column) })),
    setAutoScroll: (on) => set({ autoScroll: on }),
    setError: (message) => set({ lastError: message }),
  }
})

// Batches from the engine (and seed chunks) queue here and drain at most once per
// animation frame, so React renders once per frame no matter how many batches land.
// WKWebView pauses requestAnimationFrame while the window is hidden or minimised, but
// the engine keeps emitting; a timer fallback keeps draining then, so `pending` stays
// bounded to a fraction of a second of traffic and no exchange is ever dropped here.
const DRAIN_FALLBACK_MS = 250

const pending: Exchange[][] = []
let frameId = 0
let timerId = 0

export function enqueueExchanges(batch: readonly Exchange[] | null | undefined): void {
  if (!batch || batch.length === 0) return
  pending.push(batch as Exchange[])
  if (frameId !== 0 || timerId !== 0) return
  frameId = requestAnimationFrame(drain)
  timerId = window.setTimeout(drain, DRAIN_FALLBACK_MS)
}

/** Runs from whichever of the frame or the fallback timer fires first, and cancels the other. */
function drain(): void {
  cancelAnimationFrame(frameId)
  window.clearTimeout(timerId)
  frameId = 0
  timerId = 0
  if (pending.length === 0) return

  const { rows, received, view, filter, sort } = useExchangeStore.getState()
  const start = rows.length
  for (const batch of pending) {
    for (let i = 0; i < batch.length; i++) rows.push(batch[i])
  }
  pending.length = 0

  // Only the new rows are tested against the filter, never the whole history.
  if (view !== null) extendView(view, rows, start, filter, sort)
  useExchangeStore.setState({
    count: rows.length,
    viewCount: view === null ? rows.length : view.length,
    received: received + (rows.length - start),
  })
}
