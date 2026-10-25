import { useEffect } from 'react'
import { loadHistory, setWindowBackground, subscribeExchanges, subscribePrefs, subscribeStorageErrors } from './bridge'
import { DetailPane } from './components/DetailPane'
import { FilterBar } from './components/FilterBar'
import { HistoryGrid } from './components/HistoryGrid'
import { StatusBar } from './components/StatusBar'
import { Toolbar } from './components/Toolbar'
import { usePrefsStore } from './store/prefs'

export default function App() {
  useEffect(() => subscribeExchanges(), [])
  useEffect(() => subscribeStorageErrors(), [])
  useEffect(() => subscribePrefs(), [])
  useAppearance()
  useEffect(() => {
    void loadHistory()
  }, [])

  return (
    <div className="app">
      <Toolbar />
      <FilterBar />
      <main className="workspace">
        <HistoryGrid />
        <DetailPane />
      </main>
      <StatusBar />
    </div>
  )
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
