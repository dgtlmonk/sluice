// Thin wrapper over the Wails bindings: the only module that talks to Go.
import { History, ProxyStatus, SeedRows, StartStream, StopStream } from '../wailsjs/go/main/App'
import type { main } from '../wailsjs/go/models'
import { EventsOn } from '../wailsjs/runtime/runtime'
import { enqueueExchanges, type Exchange, useExchangeStore } from './store/exchanges'

export { ExchangeDetail, Stats } from '../wailsjs/go/main/App'

const EVENT_BATCH = 'exchanges:batch'
const EVENT_PROXY_STATUS = 'proxy:status'
const EVENT_STORAGE_ERROR = 'storage:error'
const HISTORY_ROWS = 10_000 // must not exceed maxHistoryRows in app.go

export type ProxyState = main.ProxyStatus
export type ExchangeView = main.ExchangeView
export type MessageView = main.MessageView
const SEED_CHUNK = 10_000 // must not exceed maxSeedChunk in app.go

/** Subscribes the store to engine batches. Returns the unsubscribe function. */
export function subscribeExchanges(): () => void {
  return EventsOn(EVENT_BATCH, (batch: Exchange[]) => enqueueExchanges(batch))
}

/**
 * Loads past sessions' rows from the encrypted store into the grid. The Go
 * side only returns rows stored before this launch, so they never duplicate
 * rows arriving on the live path.
 */
export async function loadHistory(): Promise<void> {
  try {
    enqueueExchanges(await History(HISTORY_ROWS))
  } catch (err) {
    useExchangeStore.getState().setError(`history: ${String(err)}`)
  }
}

/** Shows storage failures (rows that could not be saved) in the status bar. */
export function subscribeStorageErrors(): () => void {
  return EventsOn(EVENT_STORAGE_ERROR, (msg: string) => useExchangeStore.getState().setError(msg))
}

/**
 * Reports proxy listener status: the current value from the binding (the
 * startup event may fire before the webview subscribes), then any updates.
 */
export function subscribeProxyStatus(onStatus: (s: ProxyState) => void): () => void {
  let live = true
  ProxyStatus()
    .then((s) => live && onStatus(s))
    .catch((err) => live && onStatus({ listening: false, error: String(err) }))
  const off = EventsOn(EVENT_PROXY_STATUS, (s: ProxyState) => onStatus(s))
  return () => {
    live = false
    off()
  }
}

/** Seeds `total` rows in bridge-sized chunks, reporting progress as it goes. */
export async function seedRows(total: number, onProgress?: (done: number) => void): Promise<void> {
  let done = 0
  while (done < total) {
    const n = Math.min(SEED_CHUNK, total - done)
    enqueueExchanges(await SeedRows(n))
    done += n
    onProgress?.(done)
  }
}

export const startStream = (ratePerSec: number): Promise<void> => StartStream(ratePerSec)
export const stopStream = (): Promise<void> => StopStream()
