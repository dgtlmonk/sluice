import { useEffect } from 'react'
import { loadHistory, subscribeExchanges, subscribeStorageErrors } from './bridge'
import { DetailPane } from './components/DetailPane'
import { FilterBar } from './components/FilterBar'
import { HistoryGrid } from './components/HistoryGrid'
import { StatusBar } from './components/StatusBar'
import { Toolbar } from './components/Toolbar'

export default function App() {
  useEffect(() => subscribeExchanges(), [])
  useEffect(() => subscribeStorageErrors(), [])
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
