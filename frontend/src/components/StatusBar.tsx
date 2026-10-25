import { useEffect, useState } from 'react'
import { type ProxyState, Stats, subscribeProxyStatus } from '../bridge'
import { isFilterActive } from '../filter/query'
import { useFps } from '../hooks/useFps'
import { useExchangeStore } from '../store/exchanges'

const SAMPLE_MS = 500

type Live = { eventsPerSec: number; dropped: number; queued: number }

export function StatusBar() {
  const count = useExchangeStore((s) => s.count)
  const viewCount = useExchangeStore((s) => s.viewCount)
  const filtering = useExchangeStore((s) => isFilterActive(s.filter))
  const lastError = useExchangeStore((s) => s.lastError)
  const fps = useFps()
  const live = useLiveStats()
  const proxy = useProxyStatus()

  return (
    <footer className="statusbar">
      {proxy === null ? (
        <span>Proxy …</span>
      ) : proxy.listening ? (
        <span className="proxy-up">
          Proxy <b>{proxy.addr}</b>
        </span>
      ) : (
        <span className="proxy-down">proxy not listening: {proxy.error}</span>
      )}
      {filtering ? (
        <span>
          Showing <b>{viewCount.toLocaleString()}</b> of <b>{count.toLocaleString()}</b>
        </span>
      ) : (
        <span>
          Rows <b>{count.toLocaleString()}</b>
        </span>
      )}
      <span>
        Events/s <b>{live.eventsPerSec.toLocaleString()}</b>
      </span>
      <span className={live.dropped > 0 ? 'warn' : undefined}>
        Dropped <b>{live.dropped.toLocaleString()}</b>
      </span>
      <span>
        Queued <b>{live.queued.toLocaleString()}</b>
      </span>
      <span className={fps < 50 ? 'warn' : undefined}>
        FPS <b>{fps}</b>
      </span>
      {lastError && <span className="error">{lastError}</span>}
    </footer>
  )
}

function useProxyStatus(): ProxyState | null {
  const [status, setStatus] = useState<ProxyState | null>(null)
  useEffect(() => subscribeProxyStatus(setStatus), [])
  return status
}

/** Events/sec as received by the UI, plus the engine's drop counters. */
function useLiveStats(): Live {
  const [live, setLive] = useState<Live>({
    eventsPerSec: 0,
    dropped: 0,
    queued: 0,
  })

  useEffect(() => {
    let lastReceived = useExchangeStore.getState().received
    let lastAt = performance.now()
    let inFlight = false

    const timer = window.setInterval(async () => {
      const now = performance.now()
      const received = useExchangeStore.getState().received
      const eventsPerSec = Math.round(((received - lastReceived) * 1000) / (now - lastAt))
      lastReceived = received
      lastAt = now

      if (inFlight) return
      inFlight = true
      try {
        const s = await Stats()
        setLive({
          eventsPerSec,
          dropped: s.live.dropped,
          queued: s.live.queued,
        })
      } catch {
        setLive((prev) => ({ ...prev, eventsPerSec }))
      } finally {
        inFlight = false
      }
    }, SAMPLE_MS)
    return () => window.clearInterval(timer)
  }, [])

  return live
}
