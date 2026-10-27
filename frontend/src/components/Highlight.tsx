import { memo, useMemo } from 'react'
import { findAll, split, type Matcher, type Range } from '../view/search'

type MarkedProps = {
  text: string
  ranges: readonly Range[]
  /** Index in `ranges` of the match to style as current; -1 for none. */
  current?: number
}

/**
 * Text with its matches wrapped in <mark>.
 *
 * SECURITY: the text is captured traffic (untrusted). It is cut into plain
 * strings and rendered as React text children, never assembled into HTML.
 *
 * Memo: a body can carry up to HIGHLIGHT_CAP marks; moving the current match
 * re-renders only the text that holds the old or the new one.
 */
export const Marked = memo(function Marked({ text, ranges, current = -1 }: MarkedProps) {
  const pieces = useMemo(() => split(text, ranges), [text, ranges])
  if (ranges.length === 0) return <>{text}</>
  return (
    <>
      {pieces.map((p, i) =>
        p.match === null ? (
          p.text
        ) : (
          <mark key={i} className={p.match === current ? 'current' : undefined}>
            {p.text}
          </mark>
        ),
      )}
    </>
  )
})

/** Text with every match of `matcher` marked; plain text when there is no search. */
export function Highlight({ text, matcher }: { text: string; matcher: Matcher | null }) {
  const ranges = useMemo(() => (matcher ? findAll(text, matcher).ranges : NONE), [text, matcher])
  return <Marked text={text} ranges={ranges} />
}

const NONE: readonly Range[] = []
