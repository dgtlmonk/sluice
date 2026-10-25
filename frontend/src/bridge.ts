// Thin wrapper over the Wails bindings: the only module that talks to Go.
import { ProxyStatus, SeedRows, StartStream, StopStream } from '../wailsjs/go/main/App'
import type { main } from '../wailsjs/go/models'
import { EventsOn } from '../wailsjs/runtime/runtime'
import { enqueueExchanges, type Exchange } from './store/exchanges'

export { ExchangeDetail, Stats } from '../wailsjs/go/main/App'

const EVENT_BATCH = 'exchanges:batch'
const EVENT_PROXY_STATUS = 'proxy:status'

export type ProxyState = main.ProxyStatus
const SEED_CHUNK = 10_000 // must not exceed maxSeedChunk in app.go

/** Subscribes the store to engine batches. Returns the unsubscribe function. */
export function subscribeExchanges(): () => void {
  return EventsOn(EVENT_BATCH, (batch: Exchange[]) => enqueueExchanges(batch))
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
