/**
 * History filter: a tiny query language, parsed once and matched per row.
 * Pure module: no React, no store. Anything that holds rows can use it.
 *
 * Today (M0/M1) it runs in the webview over the in-memory row buffer. At M2, when
 * the grid pages rows from storage, the same query moves engine-side (translated
 * to a SQLite WHERE clause), and this file becomes the reference for its semantics.
 *
 * Syntax (see QUERY_HELP, which the filter bar shows):
 *   - Tokens are separated by whitespace; a row must match every token (AND).
 *   - `text`          case-insensitive substring of method, host, path, status or MIME.
 *   - `field:value`   host / path / method / mime: case-insensitive substring of that field.
 *   - `status:404`    exact status code; `status:4xx` a whole class (1xx..5xx).
 *   - `llm:json`      LLM rows flagged by that detection rule (path / json / sse);
 *                     `llm:any` (or `llm:yes`) every LLM row. `-llm:any` hides them.
 *   - `-token`        negates any of the above.
 *   - An unknown field (`foo:bar`) or a malformed status (`status:4x`) is not an
 *     error: the whole token is used as a plain substring instead.
 *   - Half-typed tokens (`-`, `host:`) are ignored, so the grid does not blank out
 *     while the user is still typing.
 */

/** The row fields the filter reads. Structural, so it never depends on the store. */
export type FilterableRow = {
  readonly method: string
  readonly host: string
  readonly path: string
  readonly status: number
  readonly mime: string
  readonly isLLM: boolean
  /** Detection rules that flagged the row, comma-separated ("path,sse"); empty if none. */
  readonly llmReason: string
}

const TEXT_FIELDS = ['host', 'path', 'method', 'mime'] as const
type TextField = (typeof TEXT_FIELDS)[number]

export type Term =
  | { readonly kind: 'text'; readonly negate: boolean; readonly needle: string }
  | { readonly kind: 'field'; readonly negate: boolean; readonly field: TextField; readonly needle: string }
  | { readonly kind: 'status'; readonly negate: boolean; readonly code: number }
  | { readonly kind: 'statusClass'; readonly negate: boolean; readonly hundreds: number }
  | { readonly kind: 'llm'; readonly negate: boolean; readonly rule: string | null }

export type ParsedQuery = { readonly terms: readonly Term[] }

/** The whole filter: the parsed query plus the "LLM only" toggle. */
export type RowFilter = { readonly query: ParsedQuery; readonly llmOnly: boolean }

export const NO_FILTER: RowFilter = { query: { terms: [] }, llmOnly: false }

export const QUERY_HELP: readonly string[] = [
  'Space-separated terms; a row must match all of them.',
  'openai — substring of method, host, path, status or MIME',
  'host: path: method: mime: — substring of that field',
  'status:404 — exact code',
  'status:5xx — whole class',
  'llm:any — LLM rows; llm:path, llm:json, llm:sse — by detection rule',
  '-term — negate, e.g. -method:OPTIONS',
  'Case-insensitive. Unknown fields match as plain text.',
  '/ or ⌘F to focus, Esc to clear',
]

export function parseQuery(text: string): ParsedQuery {
  const terms: Term[] = []
  for (const token of text.split(/\s+/)) {
    const term = parseToken(token)
    if (term) terms.push(term)
  }
  return { terms }
}

function parseToken(token: string): Term | null {
  const negate = token.startsWith('-')
  const body = negate ? token.slice(1) : token
  if (body === '') return null

  const colon = body.indexOf(':')
  if (colon > 0) {
    const field = body.slice(0, colon).toLowerCase()
    const value = body.slice(colon + 1)
    if (isTextField(field)) {
      return value === '' ? null : { kind: 'field', negate, field, needle: value.toLowerCase() }
    }
    if (field === 'llm') {
      if (value === '') return null
      const rule = value.toLowerCase()
      return { kind: 'llm', negate, rule: rule === 'any' || rule === 'yes' ? null : rule }
    }
    if (field === 'status') {
      if (value === '') return null
      const status = parseStatus(value)
      if (status) return { ...status, negate }
    }
  }
  return { kind: 'text', negate, needle: body.toLowerCase() }
}

function isTextField(field: string): field is TextField {
  return (TEXT_FIELDS as readonly string[]).includes(field)
}

type StatusTerm = { kind: 'status'; code: number } | { kind: 'statusClass'; hundreds: number }

function parseStatus(value: string): StatusTerm | null {
  if (/^[1-5]\d\d$/.test(value)) return { kind: 'status', code: Number(value) }
  if (/^[1-5]xx$/i.test(value)) return { kind: 'statusClass', hundreds: Number(value[0]) }
  return null
}

export function matches(row: FilterableRow, query: ParsedQuery): boolean {
  for (const term of query.terms) {
    // A hit on a negated term, or a miss on a plain one, rejects the row.
    if (testTerm(row, term) === term.negate) return false
  }
  return true
}

function testTerm(row: FilterableRow, term: Term): boolean {
  switch (term.kind) {
    case 'text':
      return (
        contains(row.method, term.needle) ||
        contains(row.host, term.needle) ||
        contains(row.path, term.needle) ||
        String(row.status).includes(term.needle) ||
        contains(row.mime, term.needle)
      )
    case 'field':
      return contains(row[term.field], term.needle)
    case 'status':
      return row.status === term.code
    case 'statusClass':
      return Math.floor(row.status / 100) === term.hundreds
    case 'llm':
      return row.isLLM && (term.rule === null || (row.llmReason ?? '').split(',').includes(term.rule))
  }
}

/** `needle` is already lower-cased by the parser. */
const contains = (haystack: string, needle: string) => haystack.toLowerCase().includes(needle)

export const isFilterActive = (filter: RowFilter): boolean => filter.llmOnly || filter.query.terms.length > 0

export const matchesFilter = (row: FilterableRow, filter: RowFilter): boolean =>
  (!filter.llmOnly || row.isLLM) && matches(row, filter.query)
