import { Link } from 'react-router-dom'
import { PLANS } from '../data/content.js'

const FAQ = [
  [
    'Is EXO-OSINT legal to use?',
    'EXO-OSINT only queries publicly available data sources. Use it for authorized security research, defensive recon and your own footprint audits — never for harassment or unauthorized surveillance.',
  ],
  [
    'Do I need API keys?',
    'No. Free sources work out of the box. Premium feeds (abuse scores, fraud scores) unlock when you add your own keys on the Operator tier.',
  ],
  [
    'Can I export results?',
    'Yes — every scan can be exported to JSON or CSV directly from the console, on every tier.',
  ],
  [
    'What counts as a scan depth?',
    'Depth 1 is fast surface recon, depth 2 adds active checks (ports, DNSBL, WHOIS), and depth 3 runs the full deep sweep with correlation.',
  ],
]

export default function Pricing() {
  return (
    <main className="page">
      <section className="container">
        <div className="section-head" style={{ textAlign: 'center' }}>
          <span className="eyebrow">// access tiers</span>
          <h2 className="mt-8" style={{ fontSize: 'clamp(30px,5vw,52px)' }}>
            Choose your clearance level
          </h2>
          <p style={{ maxWidth: 560, margin: '12px auto 0' }}>
            Transparent pricing. Cancel anytime. Every tier includes all six
            modules — higher tiers unlock depth, correlation and automation.
          </p>
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
                {p.perks.map((perk) => (
                  <li key={perk}>{perk}</li>
                ))}
              </ul>
              <Link
                to="/investigate"
                className={`btn ${p.featured ? 'btn-primary' : 'btn-ghost'}`}
              >
                {p.cta}
              </Link>
            </article>
          ))}
        </div>

        <div className="divider" style={{ marginTop: 56 }} />

        <div className="section-head" style={{ marginTop: 8 }}>
          <span className="eyebrow">// faq</span>
          <h2 className="mt-8" style={{ fontSize: 30 }}>
            Questions, answered
          </h2>
        </div>
        <div className="grid grid-2">
          {FAQ.map(([q, a]) => (
            <article key={q} className="panel corner panel-pad">
              <h3 style={{ fontSize: 16, color: 'var(--neon)' }}>{q}</h3>
              <p className="text-2 mt-8" style={{ fontSize: 14 }}>
                {a}
              </p>
            </article>
          ))}
        </div>
      </section>
    </main>
  )
}
