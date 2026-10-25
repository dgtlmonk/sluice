import { useEffect } from 'react'
import { loadHistory, setWindowBackground, stepFontSize, subscribeExchanges, subscribePrefs, subscribeStorageErrors } from './bridge'
import { DetailPane } from './components/DetailPane'
import { FilterBar } from './components/FilterBar'
import { HistoryGrid } from './components/HistoryGrid'
import { StatusBar } from './components/StatusBar'
import { Splitter, useSplit } from './components/Splitter'
import { Toolbar } from './components/Toolbar'
import { useExchangeStore } from './store/exchanges'
import { usePrefsStore } from './store/prefs'

export default function App() {
  useEffect(() => subscribeExchanges(), [])
  useEffect(() => subscribeStorageErrors(), [])
  useEffect(() => subscribePrefs(), [])
  useAppearance()
  useFontShortcuts()
  const panes = useSplit('sluice.split.history', 0.66, 0.15, 0.85)
  useEffect(() => {
    void loadHistory()
  }, [])

  return (
    <div className="app">
      <Toolbar />
      <FilterBar />
      <main
        className="workspace"
        style={{ gridTemplateRows: `minmax(80px, ${panes.fraction}fr) auto minmax(140px, ${1 - panes.fraction}fr)` }}
      >
        <HistoryGrid />
        <Splitter orientation="horizontal" split={panes} label="Resize history and detail" />
        <DetailPane />
      </main>
      <StatusBar />
    </div>
  )
}

/** Ctrl text-size keys; Cmd versions are native menu accelerators (menu.go). */
// Matched by physical key (e.code), so layouts where 0 or = need Shift work too.
const FONT_KEYS: Record<string, number> = {
  Equal: 1,
  NumpadAdd: 1,
  Minus: -1,
  NumpadSubtract: -1,
  Digit0: 0,
  Numpad0: 0,
}
// Off macOS the menu's CmdOrCtrl accelerators already own Ctrl; handling it
// here too would step twice.
const IS_MAC = navigator.platform.toUpperCase().startsWith('MAC')

function useFontShortcuts() {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!IS_MAC || !e.ctrlKey || e.metaKey || e.altKey) return
      const delta = FONT_KEYS[e.code]
      if (delta === undefined) return
      e.preventDefault()
      if (e.repeat) return // one step per press; held keys would flood Go with writes
      stepFontSize(delta).catch((err) => useExchangeStore.getState().setError(`preferences: ${String(err)}`))
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
}

/** Applies theme and base font size to the whole document, live. */
function useAppearance() {
  const theme = usePrefsStore((s) => s.effectiveTheme)
  const fontSize = usePrefsStore((s) => s.prefs.fontSize)
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    setWindowBackground(theme)
  }, [theme])
  useEffect(() => {
    document.documentElement.style.setProperty('--font-size', `${fontSize}px`)
  }, [fontSize])
}
