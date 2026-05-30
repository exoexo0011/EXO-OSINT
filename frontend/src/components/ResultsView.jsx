import { useState } from 'react'

function SevDot({ sev }) {
  return <span className={`sev-dot bg-${sev || 'info'}`} title={sev} />
}

function renderValue(v) {
  if (v === null || v === undefined) return <span className="muted">—</span>
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (Array.isArray(v)) return v.join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function ModuleBlock({ m, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen)
  const findings = m.findings || []
  return (
    <div className="module-block">
      <div className="module-head" onClick={() => setOpen((o) => !o)}>
        <span className="name">
          {open ? '▾' : '▸'} {m.module}
        </span>
        <span className="flex center gap-8">
          {m.success ? (
            <span className="tag on">{findings.length} findings</span>
          ) : (
            <span className="tag sev-high">failed</span>
          )}
        </span>
      </div>
      {open && (
        <div className="module-body">
          {m.summary && (
            <div className="finding">
              <span className="fkey">summary</span>
              <span className="fval text-2">{m.summary}</span>
            </div>
          )}
          {m.error && (
            <div className="finding">
              <span className="fkey sev-high">error</span>
              <span className="fval sev-high">{m.error}</span>
            </div>
          )}
          {findings.length === 0 && !m.error && (
            <div className="finding">
              <span className="muted">no findings returned</span>
            </div>
          )}
          {findings.map((f, i) => (
            <div className="finding" key={i}>
              <span className="fkey">
                <SevDot sev={f.severity} />
                {f.key}
              </span>
              <span className="fval">
                {f.profile_url ? (
                  <a href={f.profile_url} target="_blank" rel="noreferrer">
                    {renderValue(f.value)}
                  </a>
                ) : (
                  renderValue(f.value)
                )}{' '}
                {f.source && <span className="src">[{f.source}]</span>}
                {f.note && <span className="note">{f.note}</span>}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function ResultsView({ investigation }) {
  if (!investigation) return null
  const summary = investigation.summary || {}
  const target = investigation.targets?.[0]

  if (!target) {
    return <p className="muted">No target data in result.</p>
  }

  const score = target.footprint_score ?? summary.avg_footprint_score ?? 0
  const risk = target.risk || 'info'
  const correlations = target.correlations || []

  return (
    <div>
      {/* summary stats */}
      <div className="grid grid-3" style={{ gap: 12 }}>
        <div className="panel corner panel-pad gauge">
          <div className="ring" style={{ '--val': score }}>
            <b>{score}</b>
          </div>
          <div>
            <div className="mono-label">footprint</div>
            <div className="text-2" style={{ fontSize: 13 }}>
              digital exposure / 100
            </div>
          </div>
        </div>
        <div className="panel corner stat">
          <div className={`v sev-${risk}`} style={{ fontSize: 22, textTransform: 'uppercase' }}>
            {risk}
          </div>
          <div className="k">risk level</div>
        </div>
        <div className="panel corner stat">
          <div className="v">{summary.total_findings ?? 0}</div>
          <div className="k">findings · {summary.total_correlations ?? 0} links</div>
        </div>
      </div>

      {/* severity breakdown bar */}
      <div className="flex gap-8 wrap mt-16">
        {Object.entries(summary.severity_breakdown || {}).map(([sev, n]) => (
          <span key={sev} className="tag">
            <SevDot sev={sev} /> {sev}: {n}
          </span>
        ))}
      </div>

      {/* target header */}
      <div className="flex between center wrap mt-24" style={{ marginTop: 22 }}>
        <h3 style={{ fontSize: 18 }}>
          <span className="muted">target › </span>
          <span className="sev-low">{target.target}</span>{' '}
          <span className="tag on">{target.target_type}</span>
        </h3>
      </div>

      {/* modules */}
      {(target.modules || []).map((m, i) => (
        <ModuleBlock key={m.module + i} m={m} defaultOpen={i === 0} />
      ))}

      {/* correlations */}
      {correlations.length > 0 && (
        <div className="module-block">
          <div className="module-head">
            <span className="name">⌬ correlation links</span>
            <span className="tag on">{correlations.length}</span>
          </div>
          <div className="module-body">
            {correlations.map((c, i) => (
              <div className="corr-row" key={i}>
                <span className="tag">{c.derived_type}</span>
                <span className="sev-low">{c.derived_value}</span>
                <span className="muted">
                  via {c.seed_type} · conf {c.confidence}
                  {c.confirmed ? ' · confirmed' : ''}
                </span>
                {c.profile_url && (
                  <a href={c.profile_url} target="_blank" rel="noreferrer">
                    open ↗
                  </a>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
