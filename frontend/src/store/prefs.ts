// Appearance preferences (theme, base font size). Go owns them (prefs.json);
// this store mirrors the last value Go broadcast, so the native menu and the
// Settings panel always show the same thing.
import { create } from 'zustand'

export type Theme = 'system' | 'dark' | 'light'
export type Prefs = { theme: Theme; fontSize: number }

/** Must match fontSizes / defaultFontSize in prefs.go. */
export const FONT_SIZES = [11, 12, 13, 14, 16] as const
export const DEFAULT_PREFS: Prefs = { theme: 'system', fontSize: 12 }

/** Grid row height at the 12px base; rows scale with the font size. */
const BASE_ROW_HEIGHT = 22
const BASE_FONT_SIZE = 12

export const rowHeightFor = (fontSize: number): number => Math.round((BASE_ROW_HEIGHT * fontSize) / BASE_FONT_SIZE)

type PrefsState = {
  prefs: Prefs
  /** The theme actually shown: 'system' resolved against macOS appearance. */
  effectiveTheme: 'dark' | 'light'
  setPrefs: (p: Prefs) => void
  setSystemDark: (dark: boolean) => void
}

const darkQuery = typeof window !== 'undefined' ? window.matchMedia('(prefers-color-scheme: dark)') : null

const resolve = (theme: Theme, systemDark: boolean): 'dark' | 'light' => (theme === 'system' ? (systemDark ? 'dark' : 'light') : theme)

let systemDark = darkQuery?.matches ?? true

export const usePrefsStore = create<PrefsState>((set, get) => ({
  prefs: DEFAULT_PREFS,
  effectiveTheme: resolve(DEFAULT_PREFS.theme, systemDark),
  setPrefs: (prefs) => set({ prefs, effectiveTheme: resolve(prefs.theme, systemDark) }),
  setSystemDark: (dark) => {
    systemDark = dark
    set({ effectiveTheme: resolve(get().prefs.theme, dark) })
  },
}))

/** Calls onChange whenever macOS switches between light and dark. */
export function watchSystemTheme(onChange: (dark: boolean) => void): () => void {
  if (!darkQuery) return () => {}
  const listener = (e: MediaQueryListEvent) => onChange(e.matches)
  darkQuery.addEventListener('change', listener)
  return () => darkQuery.removeEventListener('change', listener)
}
