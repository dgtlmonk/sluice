/**
 * The History grid's view: which rows are visible and in what order, kept as
 * positions into the append-only row buffer. Combines the filter (filter/query.ts)
 * and the sort (view/sort.ts). Pure module: no React, no store.
 *
 * At M2 this whole file is replaced by engine-side paging (WHERE + ORDER BY in
 * SQLite); until then it keeps per-batch work proportional to the batch, not to
 * the history: new rows are filtered once and inserted at their sorted place.
 */
import { isFilterActive, matchesFilter, type FilterableRow, type RowFilter } from '../filter/query'
import { comparator, type SortableRow, type SortState } from './sort'

export type ViewRow = FilterableRow & SortableRow

/**
 * Positions into the row buffer, in display order. `null` means "every row, in
 * arrival order" (no filter, no sort), which spares a 100k-entry identity array.
 */
export type RowView = number[] | null

/** Full rebuild: run on a filter or sort change. */
export function buildView(rows: readonly ViewRow[], filter: RowFilter, sort: SortState | null): RowView {
  const filtering = isFilterActive(filter)
  if (!filtering && !sort) return null

  const view: number[] = []
  for (let p = 0; p < rows.length; p++) {
    if (!filtering || matchesFilter(rows[p], filter)) view.push(p)
  }
  if (sort) {
    const cmp = comparator(sort)
    view.sort((a, b) => cmp(rows[a], rows[b]))
  }
  return view
}

/**
 * Adds rows[start..] (a freshly appended batch) to `view`, in place: only the new
 * rows are filtered, and when sorted each one is binary-searched into position.
 */
export function extendView(
  view: number[],
  rows: readonly ViewRow[],
  start: number,
  filter: RowFilter,
  sort: SortState | null,
): void {
  const filtering = isFilterActive(filter)
  const added: number[] = []
  for (let p = start; p < rows.length; p++) {
    if (!filtering || matchesFilter(rows[p], filter)) added.push(p)
  }
  if (added.length === 0) return
  if (!sort) {
    for (const p of added) view.push(p)
    return
  }
  const cmp = comparator(sort)
  const byRow = (a: number, b: number) => cmp(rows[a], rows[b])
  added.sort(byRow)
  insertSorted(view, added, byRow)
}

/**
 * Inserts sorted `added` into sorted `view` in place. Works from the largest new
 * element down: binary-search its slot among the old elements not yet moved, shift
 * that tail right in one copyWithin, drop it in. Each old element moves at most once,
 * so a batch costs O(k log n) comparisons plus one pass over the rows that sort
 * after it; when new rows sort to the end (`#` or Time ascending) nothing moves.
 */
function insertSorted(view: number[], added: readonly number[], cmp: (a: number, b: number) => number): void {
  let end = view.length // view[0, end) still holds old elements in their original slots
  for (let n = 0; n < added.length; n++) view.push(0) // grow; every new slot is overwritten below

  for (let j = added.length - 1; j >= 0; j--) {
    const at = firstAfter(view, end, added[j], cmp)
    // Old elements [at, end) belong after added[j] and after the j smaller new ones still to place.
    view.copyWithin(at + j + 1, at, end)
    view[at + j] = added[j]
    end = at
  }
}

/** First index in view[0, end) whose element sorts after `x` (the order is total, so no ties). */
function firstAfter(view: readonly number[], end: number, x: number, cmp: (a: number, b: number) => number): number {
  let lo = 0
  let hi = end
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (cmp(view[mid], x) < 0) lo = mid + 1
    else hi = mid
  }
  return lo
}

/** Display index of row position `pos`, or -1 when the view hides it. */
export function indexInView(view: RowView, rowCount: number, pos: number): number {
  if (view === null) return pos < rowCount ? pos : -1
  return view.indexOf(pos)
}

/** Row position shown at display index `i`. */
export const positionAt = (view: RowView, i: number): number => (view === null ? i : view[i])
