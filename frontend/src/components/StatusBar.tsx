import { useEffect, useState } from 'react'
import { type ProxyState, Stats, subscribeProxyStatus } from '../bridge'
import { isFilterActive } from '../filter/query'
import { useFps } from '../hooks/useFps'
import { useExchangeStore } from '../store/exchanges'

const SAMPLE_MS = 500

type Storage = { available: boolean; error?: string; saved: number; lost: number; behind: number; queued: number }
type Live = { eventsPerSec: number; dropped: number; queued: number; storage: Storage | null }

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
      <StorageStatus storage={live.storage} />
      <span className={fps < 50 ? 'warn' : undefined}>
        FPS <b>{fps}</b>
      </span>
      {lastError && <span className="error">{lastError}</span>}
    </footer>
  )
}

/**
 * The lossless storage path. "Lost" (failed + refused rows) is a bug state
 * and shows as an error; "behind" means rows are waiting in memory, not lost.
 */
function StorageStatus({ storage }: { storage: Storage | null }) {
  if (storage === null) return <span>Saved …</span>
  if (!storage.available) return <span className="error">storage off: {storage.error}</span>
  return (
    <>
      <span>
        Saved <b>{storage.saved.toLocaleString()}</b>
      </span>
      {storage.lost > 0 && (
        <span className="error">
          History incomplete: <b>{storage.lost.toLocaleString()}</b> not saved
        </span>
      )}
      {storage.behind > 0 && storage.queued > 0 && (
        <span className="warn">
          Store behind <b>{storage.queued.toLocaleString()}</b>
        </span>
      )}
    </>
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
    storage: null,
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
          storage: {
            available: s.storage.available,
            error: s.storage.error,
            saved: s.storage.saved,
            lost: s.storage.failed + s.storage.unsaved,
            behind: s.storage.behind,
            queued: s.storage.queued,
          },
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
