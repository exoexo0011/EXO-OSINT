import { useEffect, useRef } from 'react'

const CLASS = {
  ok: 't-ok',
  info: 't-info',
  warn: 't-warn',
  err: 't-err',
  dim: 't-dim',
}

// Renders a scrolling, auto-following terminal feed of log lines.
// Each line: { ts, level, text }
export default function TerminalLog({ lines, running }) {
  const ref = useRef(null)

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])

  return (
    <div className="terminal" ref={ref}>
      {lines.length === 0 && (
        <div className="line t-dim">
          $ exo-osint --idle … awaiting target
        </div>
      )}
      {lines.map((l, i) => (
        <div className="line" key={i}>
          <span className="ts">{l.ts} </span>
          <span className={CLASS[l.level] || 't-dim'}>{l.text}</span>
        </div>
      ))}
      {running && <div className="line t-ok caret"> </div>}
    </div>
  )
}
