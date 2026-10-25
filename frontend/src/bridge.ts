// Thin wrapper over the Wails bindings: the only module that talks to Go.
import {
  BypassHosts,
  CAInfo,
  CATrust,
  ExportCA,
  ForgetTLSHost,
  History,
  InstallCA,
  ProxyStatus,
  SeedRows,
  SetBypassHosts,
  StartStream,
  StopStream,
  TLSHosts,
} from '../wailsjs/go/main/App'
import type { main, platform } from '../wailsjs/go/models'
import { EventsOn } from '../wailsjs/runtime/runtime'
import { enqueueExchanges, type Exchange, useExchangeStore } from './store/exchanges'

export { ExchangeDetail, ExchangeTLS, Stats } from '../wailsjs/go/main/App'

const EVENT_BATCH = 'exchanges:batch'
const EVENT_PROXY_STATUS = 'proxy:status'
const EVENT_STORAGE_ERROR = 'storage:error'
const HISTORY_ROWS = 10_000 // must not exceed maxHistoryRows in app.go

export type ProxyState = main.ProxyStatus
export type ExchangeView = main.ExchangeView
export type MessageView = main.MessageView
export type CAState = main.CAInfo
export type TrustState = platform.TrustReport
export type ExchangeTLSState = main.ExchangeTLS
export type TLSHostState = main.TLSHost
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

export const caInfo = (): Promise<CAState> => CAInfo()
export const caTrust = (): Promise<TrustState> => CATrust()
/** User-clicked only: macOS shows a password dialog. */
export const installCA = (): Promise<void> => InstallCA()
/** Returns the saved path, or '' if the user cancelled the dialog. */
export const exportCA = (): Promise<string> => ExportCA()

/** Host patterns tunnelled raw (never decrypted): "host" or "*.domain". */
export const bypassHosts = (): Promise<string[]> => BypassHosts().then((l) => l ?? [])
/** Validates, applies live and saves; resolves to the normalized list. */
export const setBypassHosts = (patterns: string[]): Promise<string[]> => SetBypassHosts(patterns).then((l) => l ?? [])
/** Hosts the engine tunnels on its own: pinning suspected, or http/1.1 refused. */
export const tlsHosts = (): Promise<TLSHostState[]> => TLSHosts().then((l) => l ?? [])
export const forgetTLSHost = (host: string): Promise<void> => ForgetTLSHost(host)
