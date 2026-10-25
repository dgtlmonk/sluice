import { useEffect, useState } from 'react'
import { ExchangeDetail } from '../bridge'
import { useExchangeStore } from '../store/exchanges'

type Raw = { request: string; response: string }

/** Raw request/response for the selected exchange, fetched from the engine on demand. */
export function DetailPane() {
  const selected = useExchangeStore((s) => s.selected)
  const [raw, setRaw] = useState<Raw | null>(null)

  useEffect(() => {
    setRaw(null)
    if (!selected) return
    let stale = false
    ExchangeDetail(selected.id)
      .then((d) => {
        if (!stale) setRaw({ request: forDisplay(d.request), response: forDisplay(d.response) })
      })
      .catch((err) => {
        if (!stale) setRaw({ request: `error: ${String(err)}`, response: '' })
      })
    return () => {
      stale = true
    }
  }, [selected])

  if (!selected) {
    return <section className="detail detail-empty">Select a row to see its request and response.</section>
  }

  return (
    <section className="detail">
      <div className="detail-col">
        <header>
          Request <span className="muted">#{selected.id}</span>
        </header>
        <pre>{raw?.request ?? ''}</pre>
      </div>
      <div className="detail-col">
        <header>
          Response{' '}
          <span className="muted">
            {selected.status} · {selected.respSize.toLocaleString()} B · {selected.durationMs} ms
          </span>
        </header>
        <pre>{raw?.response ?? ''}</pre>
      </div>
    </section>
  )
}

// Raw text keeps CRLF on the wire; show it as plain newlines.
const forDisplay = (s: string) => s.replace(/\r\n/g, '\n')
