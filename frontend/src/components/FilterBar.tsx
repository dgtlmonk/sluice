import { useEffect, useRef } from 'react'
import { QUERY_HELP } from '../filter/query'
import { useExchangeStore } from '../store/exchanges'

const DEBOUNCE_MS = 150

/** Query input + "LLM only" toggle above the History grid. Syntax lives in filter/query.ts. */
export function FilterBar() {
  const draft = useExchangeStore((s) => s.queryDraft)
  const llmOnly = useExchangeStore((s) => s.llmOnly)
  const setQueryDraft = useExchangeStore((s) => s.setQueryDraft)
  const applyQuery = useExchangeStore((s) => s.applyQuery)
  const setLlmOnly = useExchangeStore((s) => s.setLlmOnly)
  const inputRef = useRef<HTMLInputElement>(null)

  // Typing updates the draft at once; the view is rebuilt once typing pauses.
  useEffect(() => {
    const timer = window.setTimeout(() => applyQuery(draft), DEBOUNCE_MS)
    return () => window.clearTimeout(timer)
  }, [draft, applyQuery])

  // `/` (outside other inputs) or Cmd/Ctrl+F jumps to the filter.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const find = (e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'f'
      const slash = e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey && !isEditable(e.target)
      if (!find && !slash) return
      e.preventDefault()
      inputRef.current?.focus()
      inputRef.current?.select()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const clearQuery = () => {
    setQueryDraft('')
    applyQuery('') // no debounce: clearing should feel instant
  }

  return (
    <div className="filterbar">
      <div className="filter-input">
        <input
          ref={inputRef}
          type="text"
          value={draft}
          placeholder="Filter  host:openai status:5xx -method:OPTIONS"
          aria-label="Filter history"
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          autoComplete="off"
          onChange={(e) => setQueryDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== 'Escape') return
            e.preventDefault()
            if (draft !== '') clearQuery()
            else e.currentTarget.blur()
          }}
        />
        {draft !== '' && (
          <button className="filter-clear" title="Clear filter (Esc)" aria-label="Clear filter" onClick={clearQuery}>
            ✕
          </button>
        )}
      </div>
      <div className="filter-help" tabIndex={0} aria-label="Filter syntax">
        ?
        <div className="filter-help-panel" role="tooltip">
          {QUERY_HELP.map((line) => (
            <div key={line}>{line}</div>
          ))}
        </div>
      </div>
      <button
        className={'toggle llm' + (llmOnly ? ' on' : '')}
        aria-pressed={llmOnly}
        title="Show only exchanges with LLM endpoints"
        onClick={() => setLlmOnly(!llmOnly)}
      >
        LLM only
      </button>
    </div>
  )
}

function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  return target.isContentEditable || target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT'
}
