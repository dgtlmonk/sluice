import { useEffect, useState } from 'react'
import { seedRows, startStream, Stats, stopStream } from '../bridge'
import { useExchangeStore } from '../store/exchanges'
import { followsArrival } from '../view/sort'

const SEED_TOTAL = 100_000
const RATES = [1_000, 3_000, 5_000, 10_000] as const

export function Toolbar() {
  const autoScroll = useExchangeStore((s) => s.autoScroll)
  const setAutoScroll = useExchangeStore((s) => s.setAutoScroll)
  const clear = useExchangeStore((s) => s.clear)
  const setError = useExchangeStore((s) => s.setError)
  const canFollow = useExchangeStore((s) => followsArrival(s.sort))

  const [rate, setRate] = useState<number>(3_000)
  const [streaming, setStreaming] = useState(false)
  const [seeded, setSeeded] = useState<number | null>(null)

  // The engine outlives the webview (a reload keeps the stream running), so take
  // the stream state from it instead of assuming a fresh start.
  useEffect(() => {
    let stale = false
    Stats()
      .then((s) => {
        if (stale || !s.streaming) return
        setStreaming(true)
        if (s.ratePerSec > 0) setRate(s.ratePerSec)
      })
      .catch((err) => {
        if (!stale) setError(String(err))
      })
    return () => {
      stale = true
    }
  }, [setError])

  // Show a rate the engine reports even when it is not one of the presets.
  const rates: readonly number[] = RATES.includes(rate as (typeof RATES)[number]) ? RATES : [...RATES, rate].sort((a, b) => a - b)

  const run = async (action: () => Promise<void>) => {
    try {
      setError(null)
      await action()
    } catch (err) {
      setError(String(err))
    }
  }

  const onSeed = () =>
    run(async () => {
      setSeeded(0)
      try {
        await seedRows(SEED_TOTAL, setSeeded)
      } finally {
        setSeeded(null)
      }
    })

  const onToggleStream = () =>
    run(async () => {
      if (streaming) {
        await stopStream()
        setStreaming(false)
      } else {
        await startStream(rate)
        setStreaming(true)
      }
    })

  const onRate = (next: number) => {
    setRate(next)
    // Restart at the new rate when already running.
    if (streaming) void run(() => startStream(next))
  }

  return (
    <div className="toolbar">
      <span className="brand">Sluice</span>
      <span className="sep" />
      <button onClick={onSeed} disabled={seeded !== null}>
        {seeded === null ? 'Seed 100k' : `Seeding ${Math.round((seeded / SEED_TOTAL) * 100)}%`}
      </button>
      <span className="sep" />
      <label className="field">
        Rate
        <select value={rate} onChange={(e) => onRate(Number(e.target.value))}>
          {rates.map((r) => (
            <option key={r} value={r}>
              {r / 1000}k/s
            </option>
          ))}
        </select>
      </label>
      <button className={streaming ? 'danger' : 'primary'} onClick={onToggleStream}>
        {streaming ? 'Stop' : 'Start'}
      </button>
      <span className="sep" />
      <button onClick={clear}>Clear</button>
      <label
        className={'field check' + (canFollow ? '' : ' disabled')}
        title={canFollow ? undefined : 'Paused while sorted: new rows only land at the bottom in arrival order or # ascending'}
      >
        <input
          type="checkbox"
          checked={autoScroll && canFollow}
          disabled={!canFollow}
          onChange={(e) => setAutoScroll(e.target.checked)}
        />
        Auto-scroll to newest
      </label>
    </div>
  )
}
