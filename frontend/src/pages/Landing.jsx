import { Link } from 'react-router-dom'
import { FEATURES, PLANS } from '../data/content.js'

export default function Landing() {
  return (
    <main className="page">
      {/* HERO */}
      <section className="container hero">
        <span className="eyebrow">// open-source intelligence framework</span>
        <h1 style={{ marginTop: 18 }}>
          MAP THE
          <br />
          <span className="accent glitch" data-text="DIGITAL FOOTPRINT">
            DIGITAL FOOTPRINT
          </span>
        </h1>
        <p className="sub">
          Point EXO-OSINT at an IP, domain, email, username or phone number. It
          fans out across six intelligence modules, correlates the results, and
          renders the trail on a live tactical map — all from one neon terminal.
        </p>
        <div className="hero-cta">
          <Link to="/investigate" className="btn btn-primary">
            ▸ Launch Console
          </Link>
          <Link to="/pricing" className="btn btn-ghost">
            View Pricing
          </Link>
        </div>

        <div className="grid grid-4 mt-24" style={{ marginTop: 48 }}>
          {[
            ['6', 'MODULES'],
            ['85+', 'PLATFORMS'],
            ['3', 'SCAN DEPTHS'],
            ['100', 'FOOTPRINT SCORE'],
          ].map(([v, k]) => (
            <div key={k} className="panel corner stat">
              <div className="v glow-text">{v}</div>
              <div className="k">{k}</div>
            </div>
          ))}
        </div>
      </section>

      <div className="container">
        <div className="divider" />
      </div>

      {/* FEATURES */}
      <section className="container" style={{ marginTop: 24 }}>
        <div className="section-head">
          <span className="eyebrow">// capabilities</span>
          <h2 className="mt-8">Six modules. One sweep.</h2>
          <p>
            Each module is a focused collector. Run them together and the
            correlation engine stitches the signals into a single profile.
          </p>
        </div>
        <div className="grid grid-3">
          {FEATURES.map((f) => (
            <article key={f.tag} className="panel corner feature">
              <div className="ico">{f.tag}</div>
              <h3>{f.title}</h3>
              <p>{f.body}</p>
            </article>
          ))}
        </div>
      </section>

      {/* PRICING PREVIEW */}
      <section className="container" style={{ marginTop: 64 }}>
        <div className="section-head">
          <span className="eyebrow">// access tiers</span>
          <h2 className="mt-8">Pricing built for operators.</h2>
          <p>Start free. Scale into deep sweeps, correlation and monitoring.</p>
        </div>
        <div className="grid grid-3">
          {PLANS.map((p) => (
            <article
              key={p.plan}
              className={`panel corner price-card${p.featured ? ' featured' : ''}`}
            >
              {p.featured && <span className="ribbon">Most popular</span>}
              <div className="plan">{p.plan}</div>
              <div className="amount">
                {p.price} <small>{p.period}</small>
              </div>
              <ul>
                {p.perks.slice(0, 4).map((perk) => (
                  <li key={perk}>{perk}</li>
                ))}
              </ul>
              <Link
                to="/pricing"
                className={`btn ${p.featured ? 'btn-primary' : 'btn-ghost'}`}
              >
                {p.cta}
              </Link>
            </article>
          ))}
        </div>
      </section>

      {/* CLOSER */}
      <section className="container" style={{ marginTop: 64 }}>
        <div className="panel corner panel-pad" style={{ textAlign: 'center', padding: 48 }}>
          <span className="eyebrow">// ready</span>
          <h2 className="mt-8" style={{ fontSize: 34 }}>
            Run your first investigation now.
          </h2>
          <p className="text-2 mt-8" style={{ maxWidth: 520, margin: '10px auto 0' }}>
            No signup needed for a Recon-tier scan. Type a target and watch the
            terminal light up.
          </p>
          <div className="mt-24" style={{ marginTop: 26 }}>
            <Link to="/investigate" className="btn btn-primary">
              ▸ Open the Console
            </Link>
          </div>
        </div>
      </section>
    </main>
  )
}
