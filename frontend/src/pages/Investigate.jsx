import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client.js'
import ModuleSelector, { MODULE_LIST } from '../components/ModuleSelector.jsx'
import DepthSlider from '../components/DepthSlider.jsx'
import TerminalLog from '../components/TerminalLog.jsx'
import ResultsView from '../components/ResultsView.jsx'
import ResultMap from '../components/ResultMap.jsx'
import ExportButtons from '../components/ExportButtons.jsx'
import { extractMapPoints } from '../lib/results.js'

const ALL_IDS = MODULE_LIST.map((m) => m.id)

function now() {
  return new Date().toLocaleTimeString('en-GB', { hour12: false })
}

export default function Investigate() {
  const [target, setTarget] = useState('')
  const [typeOverride, setTypeOverride] = useState('auto')
  const [detected, setDetected] = useState(null)
  const [modules, setModules] = useState(ALL_IDS)
  const [correlation, setCorrelation] = useState(true)
  const [depth, setDepth] = useState(2)
  const [stealth, setStealth] = useState(false)
  const [country, setCountry] = useState('IN')

  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const timers = useRef([])
  const detectAbort = useRef(null)

  // cleanup timers on unmount
  useEffect(() => () => timers.current.forEach(clearTimeout), [])

  // debounced auto-detect as the user types
  useEffect(() => {
    const t = target.trim()
    if (!t) {
      setDetected(null)
      return
    }
    const handle = setTimeout(async () => {
      try {
        detectAbort.current?.abort()
        detectAbort.current = new AbortController()
        const res = await api.detect(t, { signal: detectAbort.current.signal })
        setDetected(res.target_type)
      } catch (e) {
        if (e?.name !== 'AbortError') setDetected(null)
      }
    }, 350)
    return () => clearTimeout(handle)
  }, [target])

  const effectiveType = typeOverride === 'auto' ? detected : typeOverride

  function toggleModule(id) {
    setModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id],
    )
  }

  function pushLine(level, text) {
    setLines((prev) => [...prev, { ts: now(), level, text }])
  }

  function scheduleFeed() {
    timers.current.forEach(clearTimeout)
    timers.current = []
    const t = target.trim()
    const type = effectiveType || 'auto'
    const steps = [
      [0, 'info', `$ exo-osint --target ${t} --depth ${depth}${stealth ? ' --stealth' : ''}`],
      [350, 'dim', `resolving target type … ${type}`],
      [800, 'ok', `target classified: ${type}`],
      [1300, 'info', `dispatching modules: ${modules.join(', ') || 'auto'}`],
    ]
    let d = 1900
    for (const id of modules) {
      steps.push([d, 'dim', `▸ running ${id} module …`])
      d += 700
    }
    if (correlation) steps.push([d, 'info', '⌬ correlation engine queued …'])
    steps.push([d + 600, 'dim', 'awaiting collector responses …'])

    steps.forEach(([delay, level, text]) => {
      timers.current.push(setTimeout(() => pushLine(level, text), delay))
    })
  }

  async function runInvestigation(e) {
    e?.preventDefault()
    const t = target.trim()
    if (!t || running) return

    setRunning(true)
    setResult(null)
    setError('')
    setLines([])
    scheduleFeed()

    const payload = {
      target: t,
      type: typeOverride === 'auto' ? null : typeOverride,
      depth,
      stealth,
      modules: modules.length === ALL_IDS.length ? 'all' : modules.join(','),
      correlation,
      country,
    }

    const started = Date.now()
    try {
      const res = await api.investigate(payload)
      timers.current.forEach(clearTimeout)
      const data = res.investigation || res
      const secs = ((Date.now() - started) / 1000).toFixed(1)
      const s = data.summary || {}
      pushLine('ok', `✓ investigation complete in ${secs}s`)
      pushLine(
        'info',
        `findings: ${s.total_findings ?? 0} · correlations: ${s.total_correlations ?? 0} · score: ${s.avg_footprint_score ?? 0}/100`,
      )
      setResult(data)
    } catch (err) {
      timers.current.forEach(clearTimeout)
      pushLine('err', `✗ ${err.message}`)
      setError(err.message)
    } finally {
      setRunning(false)
    }
  }

  const points = result ? extractMapPoints(result) : []

  return (
    <main className="page">
      <div className="container">
        <span className="eyebrow">// console</span>
        <h2 className="mt-8" style={{ fontSize: 'clamp(26px,4vw,40px)' }}>
          Investigation terminal
        </h2>
        <p className="text-2 mt-8" style={{ maxWidth: 600 }}>
          Enter a target. Type is auto-detected. Pick your modules and depth,
          then run the sweep.
        </p>

        {/* target input */}
        <form onSubmit={runInvestigation} className="mt-24" style={{ marginTop: 24 }}>
          <div className="field">
            <span className="prompt">❯</span>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="8.8.8.8  ·  example.com  ·  user@mail.com  ·  handle  ·  +14155550123"
              autoFocus
              spellCheck={false}
              autoComplete="off"
            />
            {target.trim() && (
              <span className="tag on">{detected || '…'}</span>
            )}
            <button
              type="submit"
              className="btn btn-primary btn-sm"
              disabled={running || !target.trim()}
            >
              {running ? <span className="spinner" /> : '▸ Run'}
            </button>
          </div>

          {/* controls */}
          <div className="grid grid-2 mt-24" style={{ marginTop: 20 }}>
            <div className="panel corner panel-pad">
              <ModuleSelector
                selected={modules}
                onToggle={toggleModule}
                detected={effectiveType}
              />
              <div className="flex gap-12 wrap" style={{ marginTop: 14 }}>
                <button
                  type="button"
                  className={`check${correlation ? ' on' : ''}`}
                  onClick={() => setCorrelation((c) => !c)}
                  aria-pressed={correlation}
                >
                  <span className="box">{correlation ? '✓' : ''}</span>
                  <span className="lbl">⌬ Correlation</span>
                </button>
                <button
                  type="button"
                  className={`check${stealth ? ' on' : ''}`}
                  onClick={() => setStealth((s) => !s)}
                  aria-pressed={stealth}
                >
                  <span className="box">{stealth ? '✓' : ''}</span>
                  <span className="lbl">⏱ Stealth</span>
                </button>
              </div>
            </div>

            <div className="panel corner panel-pad">
              <DepthSlider value={depth} onChange={setDepth} />
              <div className="divider" style={{ margin: '18px 0' }} />
              <div className="flex gap-16 wrap">
                <label style={{ flex: 1 }}>
                  <span className="mono-label">Type override</span>
                  <select
                    className="select"
                    style={{ width: '100%', marginTop: 6 }}
                    value={typeOverride}
                    onChange={(e) => setTypeOverride(e.target.value)}
                  >
                    <option value="auto">auto-detect</option>
                    <option value="ip">ip</option>
                    <option value="domain">domain</option>
                    <option value="email">email</option>
                    <option value="username">username</option>
                    <option value="phone">phone</option>
                  </select>
                </label>
                <label style={{ width: 120 }}>
                  <span className="mono-label">Phone region</span>
                  <input
                    type="text"
                    className="select"
                    style={{ width: '100%', marginTop: 6 }}
                    value={country}
                    onChange={(e) => setCountry(e.target.value.toUpperCase())}
                    maxLength={2}
                    spellCheck={false}
                  />
                </label>
              </div>
            </div>
          </div>
        </form>

        {error && (
          <div className="banner err mt-24" style={{ marginTop: 18 }}>
            {error}
          </div>
        )}

        {/* live output + map */}
        <div className="console-grid mt-24" style={{ marginTop: 24 }}>
          <div className="panel corner panel-pad">
            <div className="flex between center" style={{ marginBottom: 10 }}>
              <span className="mono-label">// live output</span>
              {running && <span className="tag on">running</span>}
            </div>
            <TerminalLog lines={lines} running={running} />
          </div>

          <div className="panel corner panel-pad">
            <div className="flex between center" style={{ marginBottom: 10 }}>
              <span className="mono-label">// geolocation</span>
              {points.length > 0 && (
                <span className="tag on">{points.length} node{points.length > 1 ? 's' : ''}</span>
              )}
            </div>
            <ResultMap points={points} />
          </div>
        </div>

        {/* results */}
        {result && (
          <div className="mt-24" style={{ marginTop: 28 }}>
            <div className="flex between center wrap" style={{ marginBottom: 16 }}>
              <span className="mono-label">// intelligence report</span>
              <ExportButtons investigation={result} />
            </div>
            <ResultsView investigation={result} />
          </div>
        )}
      </div>
    </main>
  )
}
