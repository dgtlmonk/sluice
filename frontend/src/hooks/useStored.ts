// Per-viewer UI memory (panel open, expanded sections) in localStorage. It is
// only a convenience: storage can be blocked or empty, so every read and
// write is guarded and any failure falls back to the default.
import { useCallback, useState } from 'react'

function read<T>(key: string, fallback: T, parse: (v: unknown) => T | undefined): T {
  try {
    const raw = localStorage.getItem(key)
    if (raw === null) return fallback
    return parse(JSON.parse(raw)) ?? fallback
  } catch {
    return fallback
  }
}

function write(key: string, v: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(v))
  } catch {
    // storage blocked: the state still works for this session
  }
}

/**
 * useState that survives restarts. `parse` validates what was stored (it is
 * outside the app's control) and returns undefined to reject it.
 */
export function useStored<T>(key: string, initial: T, parse: (v: unknown) => T | undefined): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => read(key, initial, parse))
  const set = useCallback(
    (v: T) => {
      setValue(v)
      write(key, v)
    },
    [key],
  )
  return [value, set]
}

export const asBoolean = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined)

export const asStringList = (v: unknown): string[] | undefined =>
  Array.isArray(v) && v.every((x) => typeof x === 'string') ? v : undefined
