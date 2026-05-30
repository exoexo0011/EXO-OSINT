// Module checkboxes. `correlation` is treated separately by the caller
// because the API exposes it as its own boolean flag.

const ALL = [
  { id: 'ip', label: 'IP' },
  { id: 'domain', label: 'Domain' },
  { id: 'email', label: 'Email' },
  { id: 'username', label: 'Username' },
  { id: 'phone', label: 'Phone' },
]

export default function ModuleSelector({ selected, onToggle, detected }) {
  return (
    <div>
      <div className="flex between center" style={{ marginBottom: 10 }}>
        <span className="mono-label">Modules</span>
        {detected && (
          <span className="muted" style={{ fontSize: 12 }}>
            auto-matched: <span className="sev-low">{detected}</span>
          </span>
        )}
      </div>
      <div className="grid grid-3" style={{ gap: 10 }}>
        {ALL.map((m) => {
          const on = selected.includes(m.id)
          const isMatch = detected === m.id
          return (
            <button
              key={m.id}
              type="button"
              className={`check${on ? ' on' : ''}`}
              onClick={() => onToggle(m.id)}
              aria-pressed={on}
            >
              <span className="box">{on ? '✓' : ''}</span>
              <span className="lbl">
                {m.label}
                {isMatch && <span className="sev-low"> ●</span>}
              </span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

export { ALL as MODULE_LIST }
