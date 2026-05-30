const LABELS = {
  1: ['FAST', 'surface recon — quick metadata only'],
  2: ['STANDARD', 'active checks — ports, DNSBL, WHOIS'],
  3: ['DEEP', 'full sweep — maximum collection + correlation'],
}

export default function DepthSlider({ value, onChange }) {
  const [name, desc] = LABELS[value] || LABELS[2]
  return (
    <div>
      <div className="flex between center" style={{ marginBottom: 10 }}>
        <span className="mono-label">Scan depth</span>
        <span className="tag on">
          {value} · {name}
        </span>
      </div>
      <input
        type="range"
        min="1"
        max="3"
        step="1"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        aria-label="Scan depth"
      />
      <div className="flex between" style={{ marginTop: 8, fontSize: 11 }}>
        <span className={value === 1 ? 'sev-low' : 'muted'}>FAST</span>
        <span className={value === 2 ? 'sev-low' : 'muted'}>STANDARD</span>
        <span className={value === 3 ? 'sev-low' : 'muted'}>DEEP</span>
      </div>
      <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
        {desc}
      </p>
    </div>
  )
}
