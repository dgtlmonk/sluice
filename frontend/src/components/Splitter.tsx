// Draggable divider between two panes. The split is a fraction (0..1) of the
// parent's size given to the first pane; it is remembered per viewer in
// localStorage, which is only a convenience (any failure falls back to the
// default). Pixel floors for each pane live in the parent's grid template.
import { type KeyboardEvent, type PointerEvent, useCallback, useEffect, useRef, useState } from 'react'

const clamp = (v: number, min: number, max: number) => Math.min(max, Math.max(min, v))

function readStored(key: string, fallback: number): number {
  try {
    const v = Number(localStorage.getItem(key))
    return v > 0 && v < 1 ? v : fallback
  } catch {
    return fallback
  }
}

function writeStored(key: string, v: number) {
  try {
    localStorage.setItem(key, String(v))
  } catch {
    // storage blocked: the split still works for this session
  }
}

export type Split = {
  fraction: number
  min: number
  max: number
  /** Moves the split; persist=false while dragging, true when it settles. */
  set: (v: number, persist?: boolean) => void
  reset: () => void
}

/** Split fraction for the first pane, persisted under storageKey. */
export function useSplit(storageKey: string, initial: number, min: number, max: number): Split {
  const [fraction, setFraction] = useState(() => clamp(readStored(storageKey, initial), min, max))
  const set = useCallback(
    (v: number, persist = true) => {
      const next = clamp(v, min, max)
      setFraction(next)
      if (persist) writeStored(storageKey, next)
    },
    [storageKey, min, max],
  )
  return { fraction, min, max, set, reset: () => set(initial) }
}

type Props = {
  orientation: 'horizontal' | 'vertical' // horizontal = panes stacked, bar runs left-right
  split: Split
  label: string
}

const KEY_STEP = 0.02

export function Splitter({ orientation, split, label }: Props) {
  const stacked = orientation === 'horizontal'
  // Ends an in-progress drag; also run on unmount so no listener or
  // body.resizing class outlives the component.
  const endDrag = useRef<(() => void) | null>(null)
  useEffect(() => () => endDrag.current?.(), [])

  const onPointerDown = (e: PointerEvent<HTMLDivElement>) => {
    const target = e.currentTarget
    const parent = target.parentElement
    if (!parent || e.button !== 0) return
    e.preventDefault() // no text selection while dragging
    target.focus() // preventDefault skips the focus a click would give
    target.setPointerCapture(e.pointerId)
    const rect = parent.getBoundingClientRect()
    const at = (ev: globalThis.PointerEvent) =>
      stacked ? (ev.clientY - rect.top) / rect.height : (ev.clientX - rect.left) / rect.width
    let last = split.fraction
    const move = (ev: globalThis.PointerEvent) => {
      last = at(ev)
      split.set(last, false)
    }
    const end = () => {
      target.removeEventListener('pointermove', move)
      for (const t of ['pointerup', 'pointercancel', 'lostpointercapture'] as const) target.removeEventListener(t, end)
      document.body.classList.remove('resizing')
      endDrag.current = null
      split.set(last) // persist once, when the drag settles
    }
    target.addEventListener('pointermove', move)
    for (const t of ['pointerup', 'pointercancel', 'lostpointercapture'] as const) target.addEventListener(t, end)
    document.body.classList.add('resizing')
    endDrag.current = end
  }

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const back = stacked ? 'ArrowUp' : 'ArrowLeft'
    const fwd = stacked ? 'ArrowDown' : 'ArrowRight'
    if (e.key === back) split.set(split.fraction - KEY_STEP)
    else if (e.key === fwd) split.set(split.fraction + KEY_STEP)
    else if (e.key === 'Home') split.reset()
    else return
    e.preventDefault()
  }

  return (
    <div
      className={`splitter splitter-${orientation}`}
      role="separator"
      aria-label={label}
      aria-orientation={orientation}
      aria-valuemin={Math.round(split.min * 100)}
      aria-valuemax={Math.round(split.max * 100)}
      aria-valuenow={Math.round(split.fraction * 100)}
      tabIndex={0}
      onPointerDown={onPointerDown}
      onKeyDown={onKeyDown}
      onDoubleClick={split.reset}
    />
  )
}
