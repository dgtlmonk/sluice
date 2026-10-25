/**
 * History sort: one column at a time, cycling asc -> desc -> off (arrival order).
 * Pure module: no React, no store.
 *
 * Today (M0/M1) the webview sorts its in-memory rows. At M2, when the grid pages
 * rows from storage, sorting moves engine-side alongside the filter (SQL ORDER BY
 * <column>, id), and these comparators define the order it must reproduce.
 */

/** The row fields the sort reads. Structural, so it never depends on the store. */
export type SortableRow = {
  readonly id: number
  readonly method: string
  readonly scheme: string
  readonly host: string
  readonly port: number
  readonly path: string
  readonly status: number
  readonly respSize: number
  readonly mime: string
  readonly startedAt: number
  readonly isLLM: boolean
}

/** Matches the grid's column ids. */
export type SortColumn = 'id' | 'method' | 'host' | 'path' | 'status' | 'respSize' | 'mime' | 'startedAt' | 'isLLM'

export type SortDir = 'asc' | 'desc'

export type SortState = { readonly column: SortColumn; readonly dir: SortDir }

type Compare = (a: SortableRow, b: SortableRow) => number

const byNumber = (a: number, b: number) => a - b
// Ordinal, not localeCompare: hosts, methods and MIME types are ASCII, and ordinal
// keeps a 100k-row re-sort fast and its order identical to SQLite's default BINARY collation.
const byString = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0)

const COLUMN_COMPARE: Readonly<Record<SortColumn, Compare>> = {
  id: (a, b) => byNumber(a.id, b.id),
  method: (a, b) => byString(a.method, b.method),
  // Group by host name first; scheme and port only break ties.
  host: (a, b) => byString(a.host, b.host) || byNumber(a.port, b.port) || byString(a.scheme, b.scheme),
  path: (a, b) => byString(a.path, b.path),
  status: (a, b) => byNumber(a.status, b.status),
  respSize: (a, b) => byNumber(a.respSize, b.respSize),
  mime: (a, b) => byString(a.mime, b.mime),
  startedAt: (a, b) => byNumber(a.startedAt, b.startedAt),
  isLLM: (a, b) => byNumber(Number(a.isLLM), Number(b.isLLM)),
}

/**
 * Total order for a sort: the column (reversed for desc), then id ascending.
 * Ids are unique, so no two rows ever compare equal; that is what makes binary
 * search insertion of new rows land in exactly one place.
 */
export function comparator(sort: SortState): Compare {
  const column = COLUMN_COMPARE[sort.column]
  const sign = sort.dir === 'asc' ? 1 : -1
  return (a, b) => sign * column(a, b) || a.id - b.id
}

/** Header click: a new column starts ascending; the same column goes asc -> desc -> off. */
export function nextSort(current: SortState | null, column: SortColumn): SortState | null {
  if (!current || current.column !== column) return { column, dir: 'asc' }
  return current.dir === 'asc' ? { column, dir: 'desc' } : null
}

/**
 * New rows arrive at the tail only in arrival order or `#` ascending (ids grow
 * with arrival), so those are the only orders where following the tail means anything.
 */
export const followsArrival = (sort: SortState | null): boolean =>
  sort === null || (sort.column === 'id' && sort.dir === 'asc')
