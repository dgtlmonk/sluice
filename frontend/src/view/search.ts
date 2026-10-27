/**
 * Plain-text, case-insensitive search for the detail pane (like Burp's
 * message-editor search). Pure module: no React.
 *
 * The query is user text, so it is never used as a pattern: every regex
 * metacharacter is escaped first. A regex (rather than lowercasing both
 * strings and using indexOf) keeps match offsets in the original text:
 * lowercasing can change a string's length (`İ` becomes two code units),
 * which would shift every highlight after it.
 */

/** Highlights rendered per message; past this, matches are counted but not marked. */
export const HIGHLIGHT_CAP = 1000

/** A match as [start, end) offsets into the searched text. */
export type Range = readonly [number, number]

export type Matcher = {
  /** Stateless: for yes/no tests. */
  readonly test: RegExp
  /** Global, for walking matches. Its lastIndex is reset on every use. */
  readonly all: RegExp
}

const REGEX_SYNTAX = /[.*+?^${}()|[\]\\]/g

/** Returns null for an empty query: no search, show everything. */
export function makeMatcher(query: string): Matcher | null {
  if (query === '') return null
  const source = query.replace(REGEX_SYNTAX, '\\$&')
  return { test: new RegExp(source, 'i'), all: new RegExp(source, 'gi') }
}

export function matches(text: string, m: Matcher): boolean {
  return m.test.test(text)
}

/** Characters kept before the first match when a clipped text is shown from it. */
export const HIT_LEAD = 12

/**
 * The text from just before its first match, behind an ellipsis; the whole
 * text when there is none or it is near the start. For a cell that clips at
 * its edge: the match stays in view instead of past the ellipsis.
 */
export function fromFirstHit(text: string, m: Matcher, lead = HIT_LEAD): string {
  // `test` is not global, so exec keeps no state between calls.
  const at = m.test.exec(text)?.index ?? -1
  if (at <= lead) return text
  let from = at - lead
  // Never cut a surrogate pair (an emoji, say) in half: step back onto its first unit.
  const unit = text.charCodeAt(from)
  if (unit >= 0xdc00 && unit <= 0xdfff) from--
  return `…${text.slice(from)}`
}

export type Found = {
  /** At most `cap` ranges, in text order. */
  readonly ranges: readonly Range[]
  /** Every match in the text, including those past the cap. */
  readonly total: number
}

/** Finds every match; keeps offsets for the first `cap` of them. */
export function findAll(text: string, m: Matcher, cap = HIGHLIGHT_CAP): Found {
  const ranges: Range[] = []
  let total = 0
  const re = m.all
  re.lastIndex = 0
  // The query is never empty, so every match has length > 0 and the loop advances.
  for (let hit = re.exec(text); hit !== null; hit = re.exec(text)) {
    if (total < cap) ranges.push([hit.index, hit.index + hit[0].length])
    total++
  }
  return { ranges, total }
}

/** A piece of text that is (mark) or is not a match, with its match number. */
export type Piece = { readonly text: string; readonly match: number | null }

/** Cuts text at the ranges, so a view can wrap the matches in <mark>. */
export function split(text: string, ranges: readonly Range[]): Piece[] {
  const pieces: Piece[] = []
  let at = 0
  ranges.forEach(([start, end], i) => {
    if (start > at) pieces.push({ text: text.slice(at, start), match: null })
    pieces.push({ text: text.slice(start, end), match: i })
    at = end
  })
  if (at < text.length) pieces.push({ text: text.slice(at), match: null })
  return pieces
}
