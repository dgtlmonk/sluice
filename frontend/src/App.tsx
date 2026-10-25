import { useEffect } from 'react'
import { subscribeExchanges } from './bridge'
import { DetailPane } from './components/DetailPane'
import { FilterBar } from './components/FilterBar'
import { HistoryGrid } from './components/HistoryGrid'
import { StatusBar } from './components/StatusBar'
import { Toolbar } from './components/Toolbar'

export default function App() {
  useEffect(() => subscribeExchanges(), [])

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
