"""Professional HTML / JSON / CSV reports for EXO-OSINT v2.0.

The HTML report embeds the full investigation JSON inline and uses Leaflet +
Chart.js (loaded via CDN) for an interactive dashboard. Designed to look
polished even with the data folded into a single self-contained file.
"""

from __future__ import annotations

import csv
import html
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .types import Investigation, ModuleResult, TargetReport


# ---------------------------------------------------------------------------
# JSON / CSV
# ---------------------------------------------------------------------------

def write_json(investigation: Investigation, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(investigation.to_dict(), f, indent=2, default=str)
    return path


def write_csv(investigation: Investigation, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["target", "target_type", "module", "key", "value",
                    "severity", "source", "note", "profile_url"])
        for t in investigation.targets:
            for m in t.modules:
                if not m.findings:
                    w.writerow([t.target, t.target_type, m.module, "", "",
                                "info", "", "no findings", ""])
                for finding in m.findings:
                    val = finding.value
                    if isinstance(val, (list, dict)):
                        val = json.dumps(val, default=str, ensure_ascii=False)
                    w.writerow([
                        t.target, t.target_type, m.module,
                        finding.key, val, finding.severity, finding.source,
                        finding.note, finding.profile_url or "",
                    ])
    return path


# ---------------------------------------------------------------------------
# Stdout text rendering
# ---------------------------------------------------------------------------

def render_text(investigation: Investigation) -> str:
    out: List[str] = []
    out.append("=" * 78)
    out.append("EXO-OSINT REPORT")
    out.append("=" * 78)
    s = investigation.summary or {}
    out.append(f"targets: {s.get('total_targets', 0)} | findings: {s.get('total_findings', 0)}")
    out.append(f"avg footprint score: {s.get('avg_footprint_score', 0)}/100")
    out.append(f"risk: {s.get('risk_breakdown', {})}")
    out.append(f"correlations: {s.get('total_correlations', 0)}")
    for t in investigation.targets:
        out.append("")
        out.append("-" * 78)
        out.append(
            f"TARGET: {t.target}  [{t.target_type}]  "
            f"risk={t.risk_level()}  score={t.footprint_score()}/100"
        )
        out.append("-" * 78)
        for m in t.modules:
            summary = f"  ({m.summary})" if m.summary else ""
            out.append(f"  [{m.module}] success={m.success} error={m.error or '-'}{summary}")
            for f in m.findings:
                val = f.value
                if isinstance(val, (list, dict)):
                    val = json.dumps(val, default=str)
                val_str = str(val)
                if len(val_str) > 200:
                    val_str = val_str[:200] + "…"
                out.append(f"    - {f.key:32s} [{f.severity:8s}] {val_str}")
        if t.correlations:
            out.append(f"  [correlation links]")
            for c in t.correlations:
                out.append(
                    f"    - {c.derived_type:9s} {c.derived_value!s:40s} "
                    f"confidence={c.confidence:6s} confirmed={c.confirmed} "
                    f"({c.source})"
                )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML — themed dashboard
# ---------------------------------------------------------------------------

CSS = """
:root[data-theme="dark"] {
  --bg: #0a0a0f;
  --bg2: #12121a;
  --bg3: #1a1a26;
  --bg4: #221a30;
  --primary: #9d4edd;
  --accent: #c77dff;
  --accent-bright: #e0aaff;
  --text: #e0e0e0;
  --text-dim: #9b9bad;
  --danger: #ff4d6d;
  --success: #06d6a0;
  --warning: #ffd166;
  --border: #2a1a3a;
  --shadow: rgba(157,78,221,0.25);
}
:root[data-theme="light"] {
  --bg: #f5f3fa;
  --bg2: #ffffff;
  --bg3: #faf7ff;
  --bg4: #f0e8fb;
  --primary: #7b3eb8;
  --accent: #9d4edd;
  --accent-bright: #6a2ca8;
  --text: #1a1a26;
  --text-dim: #555566;
  --danger: #c92347;
  --success: #018f6a;
  --warning: #b07a00;
  --border: #d8c6e9;
  --shadow: rgba(157,78,221,0.15);
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg);
  color: var(--text);
  font-family: 'Share Tech Mono', 'Courier New', monospace;
  min-height: 100vh;
  scroll-behavior: smooth;
}
body {
  background:
    radial-gradient(ellipse at top left, rgba(157,78,221,0.10), transparent 40%),
    radial-gradient(ellipse at bottom right, rgba(199,125,255,0.06), transparent 50%),
    var(--bg);
}

/* Layout */
.layout { display: flex; min-height: 100vh; }
aside.sidebar {
  width: 260px;
  flex-shrink: 0;
  background: var(--bg2);
  border-right: 1px solid var(--border);
  padding: 22px 12px;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
}
aside.sidebar h2 {
  color: var(--accent);
  text-shadow: 0 0 8px var(--shadow);
  letter-spacing: 3px;
  font-size: 0.95rem;
  margin: 0 0 18px 0;
  padding: 0 8px;
}
aside.sidebar .nav-item {
  display: block;
  padding: 8px 10px;
  margin: 2px 0;
  border-radius: 4px;
  color: var(--text);
  text-decoration: none;
  border-left: 2px solid transparent;
  font-size: 0.84rem;
  transition: all .15s;
  word-break: break-all;
}
aside.sidebar .nav-item:hover {
  background: var(--bg3);
  border-left-color: var(--accent);
  color: var(--accent);
}
aside.sidebar .nav-item .type {
  color: var(--text-dim);
  font-size: 0.7rem;
  margin-left: 4px;
}
aside.sidebar .nav-item .score {
  float: right;
  background: var(--bg4);
  padding: 1px 6px;
  border-radius: 999px;
  font-size: 0.7rem;
  color: var(--accent);
}
aside.sidebar .toolbox {
  margin-top: 18px;
  padding: 10px;
  border-top: 1px dashed var(--border);
}
aside.sidebar .tool-btn {
  display: block;
  width: 100%;
  margin: 6px 0;
  padding: 8px;
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--accent);
  font-family: inherit;
  font-size: 0.78rem;
  cursor: pointer;
  letter-spacing: 1px;
  transition: all .15s;
}
aside.sidebar .tool-btn:hover {
  background: var(--accent);
  color: var(--bg);
  box-shadow: 0 0 12px var(--shadow);
}

main.content {
  flex: 1;
  padding: 28px 36px 80px;
  min-width: 0;
}

/* Banner */
header.banner {
  text-align: center;
  padding: 22px 16px;
  border: 1px solid var(--primary);
  border-radius: 8px;
  background: linear-gradient(180deg, rgba(157,78,221,0.10), rgba(157,78,221,0.02));
  box-shadow: 0 0 40px var(--shadow), inset 0 0 30px rgba(157,78,221,0.05);
  margin-bottom: 24px;
  position: relative;
  overflow: hidden;
}
header.banner::before {
  content: "";
  position: absolute; top: 0; left: -100%;
  width: 30%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(199,125,255,0.18), transparent);
  animation: scan 4s ease-in-out infinite;
  pointer-events: none;
}
@keyframes scan {
  0% { left: -30%; }
  60% { left: 130%; }
  100% { left: 130%; }
}
header.banner pre {
  text-align: left; display: inline-block;
  margin: 0 0 8px 0; font-size: 0.65rem; line-height: 1;
  color: var(--accent);
  text-shadow: 0 0 12px var(--shadow);
  overflow-x: auto;
}
header.banner .tagline {
  color: var(--accent);
  font-size: 0.95rem;
  letter-spacing: 2px;
}
header.banner .subtag {
  color: var(--text-dim);
  font-size: 0.78rem;
  margin-top: 4px;
}
header.banner .meta {
  margin-top: 10px;
  display: flex; flex-wrap: wrap; gap: 10px; justify-content: center;
  font-size: 0.78rem; color: var(--text-dim);
}

/* Cards */
section.exec {
  margin: 18px 0 24px 0;
  padding: 20px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg2);
  box-shadow: 0 0 18px var(--shadow);
}
section.exec h2 {
  color: var(--accent);
  margin: 0 0 14px 0;
  font-size: 1.1rem;
  letter-spacing: 2px;
  text-shadow: 0 0 6px var(--shadow);
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px,1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.card {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  background: var(--bg3);
}
.card .label {
  color: var(--text-dim);
  font-size: 0.72rem;
  letter-spacing: 1px;
  text-transform: uppercase;
}
.card .value {
  color: var(--accent);
  font-size: 1.5rem;
  margin-top: 4px;
  text-shadow: 0 0 6px var(--shadow);
}

/* Map + charts row */
.dashboard-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  margin-bottom: 24px;
}
@media (max-width: 1100px) { .dashboard-row { grid-template-columns: 1fr; } }
.panel {
  border: 1px solid var(--border);
  background: var(--bg2);
  border-radius: 8px;
  padding: 14px 16px;
  min-height: 240px;
}
.panel h3 {
  color: var(--accent);
  font-size: 0.9rem;
  letter-spacing: 2px;
  margin: 0 0 10px 0;
}
#map { height: 340px; border-radius: 6px; background: #000; }
.chart-wrapper { height: 340px; position: relative; }

/* Targets */
.target {
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 22px;
  background: var(--bg2);
  overflow: hidden;
  scroll-margin-top: 8px;
}
.target > summary {
  list-style: none;
  cursor: pointer;
  padding: 14px 18px;
  background: linear-gradient(90deg, rgba(157,78,221,0.18), rgba(157,78,221,0.03));
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  flex-wrap: wrap;
}
.target > summary::-webkit-details-marker { display: none; }
.target > summary .title {
  color: var(--accent);
  font-size: 1.05rem;
  letter-spacing: 1px;
}
.target > summary .title .type {
  color: var(--text-dim);
  font-size: 0.78rem;
  margin-left: 8px;
}
.score-bar {
  display: inline-block;
  width: 110px; height: 8px;
  background: var(--bg4);
  border-radius: 4px; overflow: hidden;
  vertical-align: middle;
  margin-right: 8px;
}
.score-bar > span {
  display: block; height: 100%;
  background: linear-gradient(90deg, var(--success), var(--warning) 60%, var(--danger));
}
.score-num { color: var(--accent); margin-right: 6px; }

.module {
  padding: 14px 18px;
  border-top: 1px dashed var(--border);
}
.module:first-of-type { border-top: none; }
.module > summary {
  list-style: none;
  cursor: pointer;
  padding: 6px 0;
  color: var(--accent);
  letter-spacing: 1px;
}
.module > summary::-webkit-details-marker { display: none; }
.module > summary::before { content: "▸ "; color: var(--primary); }
.module[open] > summary::before { content: "▾ "; }
.module .module-summary {
  color: var(--text-dim);
  font-size: 0.78rem;
  font-style: italic;
  margin: 4px 0 8px 0;
}

/* Findings table */
table.findings { width: 100%; border-collapse: collapse; margin-top: 8px; }
table.findings th, table.findings td {
  text-align: left;
  padding: 7px 9px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  font-size: 0.85rem;
  word-break: break-word;
}
table.findings th {
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 1px;
  font-size: 0.7rem;
}
table.findings td.k { color: var(--accent); white-space: nowrap; }
table.findings td.v { color: var(--text); }
table.findings td pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: inherit;
  color: var(--text);
}
table.findings td a {
  color: var(--accent-bright);
  text-decoration: none;
  border-bottom: 1px dashed var(--accent-bright);
}
table.findings td a:hover { color: var(--accent); }

img.avatar {
  width: 28px; height: 28px;
  border-radius: 50%;
  vertical-align: middle;
  margin-right: 6px;
  border: 1px solid var(--border);
}
img.screenshot {
  max-width: 220px;
  border: 1px solid var(--border);
  border-radius: 4px;
  margin-top: 4px;
}

.copy-btn {
  cursor: pointer;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--accent);
  font-family: inherit;
  font-size: 0.7rem;
  padding: 1px 6px;
  border-radius: 4px;
  margin-left: 6px;
  opacity: 0.5;
  transition: all .15s;
}
.copy-btn:hover { opacity: 1; background: var(--bg3); }

.badge {
  display: inline-block;
  padding: 2px 9px;
  border-radius: 999px;
  font-size: 0.68rem;
  letter-spacing: 1px;
  text-transform: uppercase;
  border: 1px solid var(--primary);
  color: var(--accent);
  background: rgba(157,78,221,0.10);
  box-shadow: 0 0 8px var(--shadow);
}
.badge.info { border-color: var(--primary); color: var(--accent); }
.badge.low { border-color: var(--success); color: var(--success); box-shadow: 0 0 8px rgba(6,214,160,0.35); }
.badge.medium { border-color: var(--warning); color: var(--warning); box-shadow: 0 0 8px rgba(255,209,102,0.35); }
.badge.high { border-color: var(--danger); color: var(--danger); box-shadow: 0 0 8px rgba(255,77,109,0.40); }
.badge.critical { border-color: var(--danger); color: #fff; background: var(--danger); box-shadow: 0 0 14px var(--danger); }

.kvpair { color: var(--text-dim); font-size: 0.8rem; }

/* Correlation panel */
.correlations {
  padding: 12px 18px 18px 18px;
  border-top: 2px solid var(--border);
  background: var(--bg3);
}
.correlations h4 {
  color: var(--accent);
  font-size: 0.9rem;
  letter-spacing: 1px;
  margin: 0 0 10px 0;
}
.corr-link {
  display: inline-block;
  margin: 4px 6px 4px 0;
  padding: 6px 10px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--bg2);
  font-size: 0.78rem;
}
.corr-link.confirmed {
  border-color: var(--success);
  color: var(--success);
  box-shadow: 0 0 6px rgba(6,214,160,0.3);
}
.corr-link .ctype {
  color: var(--text-dim);
  font-size: 0.7rem;
  text-transform: uppercase;
  margin-right: 6px;
}

/* Timeline */
.timeline {
  margin-top: 10px;
  padding: 8px 14px 8px 30px;
  border-left: 2px dashed var(--border);
  font-size: 0.78rem;
}
.timeline .row { color: var(--text-dim); margin: 3px 0; }
.timeline .row b { color: var(--accent); }

footer.foot {
  margin-top: 36px;
  text-align: center;
  color: var(--text-dim);
  font-size: 0.78rem;
  border-top: 1px solid var(--border);
  padding-top: 18px;
}

@media (max-width: 800px) {
  .layout { flex-direction: column; }
  aside.sidebar { width: 100%; height: auto; position: static; border-right: none; border-bottom: 1px solid var(--border); }
  main.content { padding: 18px; }
}

/* ============================================================ */
/* Dating Footprint section                                     */
/* ============================================================ */
.dt-section {
  border: 1px solid var(--border);
  background: linear-gradient(180deg, rgba(255,77,109,0.08), rgba(157,78,221,0.04));
  border-radius: 8px;
  padding: 14px 18px 18px 18px;
  margin: 14px 0 6px 0;
}
.dt-section > summary { list-style: none; cursor: pointer; }
.dt-section > summary::-webkit-details-marker { display: none; }
.dt-summary {
  display: flex; justify-content: space-between; align-items: center;
  gap: 12px; flex-wrap: wrap;
}
.dt-title {
  color: var(--accent-bright);
  font-size: 1.05rem;
  letter-spacing: 2px;
  text-shadow: 0 0 8px var(--shadow);
}
.dt-count-summary { color: var(--text-dim); font-size: 0.78rem; }
.dt-legend {
  display: flex; gap: 14px; flex-wrap: wrap;
  margin: 10px 0 14px 0;
  padding: 6px 10px;
  background: var(--bg2);
  border: 1px dashed var(--border);
  border-radius: 6px;
  font-size: 0.74rem;
}
.dt-leg.low { color: var(--success); }
.dt-leg.medium { color: var(--warning); }
.dt-leg.high { color: var(--danger); }

.dt-group { margin-top: 14px; }
.dt-group-title {
  font-size: 0.78rem; letter-spacing: 2px;
  margin: 0 0 8px 0;
  padding-left: 8px;
  border-left: 3px solid var(--accent);
}
.dt-group-title.low { border-left-color: var(--success); color: var(--success); }
.dt-group-title.medium { border-left-color: var(--warning); color: var(--warning); }
.dt-group-title.high { border-left-color: var(--danger); color: var(--danger); }
.dt-count { color: var(--text-dim); font-weight: normal; }

.dt-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 8px;
}
.dt {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg3);
  text-decoration: none;
  transition: all .12s;
}
.dt:hover { transform: translateY(-1px); }
.dt-icon {
  width: 26px; height: 26px;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-weight: bold; font-size: 0.85rem;
  flex-shrink: 0;
}
.dt-body { display: flex; flex-direction: column; min-width: 0; }
.dt-body b { color: var(--text); font-size: 0.85rem; word-break: break-word; }
.dt-sub { color: var(--text-dim); font-size: 0.7rem; }

.dt.confirmed {
  border-color: var(--success);
  background: rgba(6,214,160,0.10);
  box-shadow: 0 0 8px rgba(6,214,160,0.25);
}
.dt.confirmed:hover { box-shadow: 0 0 14px rgba(6,214,160,0.45); }
.dt.confirmed .dt-icon { background: var(--success); color: #000; }
.dt.confirmed b { color: var(--success); }

.dt.low {
  border-color: rgba(6,214,160,0.4);
}
.dt.low .dt-icon { background: var(--success); color: #000; opacity: 0.8; }

.dt.medium { border-color: rgba(255,209,102,0.5); }
.dt.medium .dt-icon { background: var(--warning); color: #000; }
.dt.medium:hover { box-shadow: 0 0 10px rgba(255,209,102,0.35); }

.dt.high { border-color: rgba(255,77,109,0.5); }
.dt.high .dt-icon { background: var(--danger); color: #fff; }
.dt.high:hover { box-shadow: 0 0 10px rgba(255,77,109,0.45); }

.dt-breach {
  background: rgba(255,77,109,0.08);
  border: 1px solid var(--danger);
  border-radius: 6px;
  padding: 12px 14px;
  box-shadow: 0 0 12px rgba(255,77,109,0.20);
}
.dt-breach-note {
  color: var(--text);
  font-size: 0.82rem;
  margin-bottom: 10px;
}
.dt-breach-chips {
  display: flex; flex-wrap: wrap; gap: 6px;
}
.dt-breach-chip {
  padding: 4px 10px;
  border-radius: 999px;
  background: var(--danger);
  color: #fff;
  font-size: 0.74rem;
  letter-spacing: 1px;
  text-shadow: 0 0 6px rgba(0,0,0,0.4);
}
"""

JS = """
(function() {
  const data = JSON.parse(document.getElementById('exo-data').textContent);

  // -------- theme toggle --------
  const root = document.documentElement;
  const stored = localStorage.getItem('exo-theme');
  if (stored) root.setAttribute('data-theme', stored);
  const themeBtn = document.getElementById('btn-theme');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      localStorage.setItem('exo-theme', next);
    });
  }

  // -------- copy-to-clipboard buttons --------
  document.body.addEventListener('click', (e) => {
    if (e.target && e.target.classList && e.target.classList.contains('copy-btn')) {
      const text = e.target.getAttribute('data-copy') || '';
      navigator.clipboard.writeText(text).then(
        () => {
          const old = e.target.textContent;
          e.target.textContent = 'copied!';
          setTimeout(() => { e.target.textContent = old; }, 1100);
        },
        () => { e.target.textContent = 'err'; }
      );
    }
  });

  // -------- export buttons --------
  function downloadFile(name, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
  const exportJson = document.getElementById('btn-export-json');
  if (exportJson) {
    exportJson.addEventListener('click', () => {
      downloadFile('exo-osint.json', JSON.stringify(data, null, 2), 'application/json');
    });
  }
  const exportCsv = document.getElementById('btn-export-csv');
  if (exportCsv) {
    exportCsv.addEventListener('click', () => {
      const rows = [['target','target_type','module','key','value','severity','source','note','profile_url']];
      function csvEscape(v) {
        if (v === null || v === undefined) return '';
        const s = (typeof v === 'string') ? v : JSON.stringify(v);
        if (s.search(/[",\\n]/) === -1) return s;
        return '"' + s.replace(/"/g,'""') + '"';
      }
      data.targets.forEach(t => {
        (t.modules||[]).forEach(m => {
          (m.findings||[]).forEach(f => {
            rows.push([t.target, t.target_type, m.module, f.key, f.value,
                       f.severity, f.source, f.note, f.profile_url||'']
                       .map(csvEscape).join(','));
          });
        });
      });
      downloadFile('exo-osint.csv', rows.map(r => Array.isArray(r) ? r.map(csvEscape).join(',') : r).join('\\n'),
                   'text/csv');
    });
  }

  // -------- Leaflet map --------
  const points = [];
  data.targets.forEach(t => {
    (t.modules||[]).forEach(m => {
      if (m.module === 'ip' && m.data && m.data.lat !== undefined && m.data.lon !== undefined) {
        points.push({
          lat: m.data.lat, lon: m.data.lon,
          target: t.target,
          info: (m.data.geo && m.data.geo.country) ? m.data.geo.country : '',
          isp: (m.data.geo && m.data.geo.isp) ? m.data.geo.isp : ''
        });
      }
    });
  });
  if (typeof L !== 'undefined' && document.getElementById('map')) {
    const map = L.map('map', { worldCopyJump: true, zoomControl: true });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap & CARTO',
      maxZoom: 8
    }).addTo(map);
    if (points.length === 0) {
      map.setView([20, 0], 2);
      L.marker([20, 0]).bindPopup('No IP geolocation in this report').addTo(map);
    } else {
      const group = L.featureGroup();
      points.forEach(p => {
        const m = L.circleMarker([p.lat, p.lon], {
          radius: 9, color: '#c77dff', fillColor: '#9d4edd',
          fillOpacity: 0.7, weight: 2
        });
        m.bindPopup('<b>' + p.target + '</b><br>' + p.info + '<br>' + p.isp);
        m.addTo(group);
      });
      group.addTo(map);
      map.fitBounds(group.getBounds().pad(0.5));
      if (points.length === 1) map.setZoom(4);
    }
  }

  // -------- Chart.js charts --------
  if (typeof Chart !== 'undefined') {
    const sev = (data.summary && data.summary.severity_breakdown) || {};
    const sevCtx = document.getElementById('sev-chart');
    if (sevCtx) {
      new Chart(sevCtx, {
        type: 'doughnut',
        data: {
          labels: ['info', 'low', 'medium', 'high', 'critical'],
          datasets: [{
            data: [sev.info||0, sev.low||0, sev.medium||0, sev.high||0, sev.critical||0],
            backgroundColor: ['#9d4edd','#06d6a0','#ffd166','#ff7e8b','#ff4d6d'],
            borderColor: '#0a0a0f', borderWidth: 1
          }]
        },
        options: {
          plugins: {
            legend: { position: 'bottom', labels: { color: '#c77dff' } },
            title: { display: false }
          },
          responsive: true, maintainAspectRatio: false
        }
      });
    }
    const fpCtx = document.getElementById('fp-chart');
    if (fpCtx) {
      const targets = data.targets || [];
      new Chart(fpCtx, {
        type: 'bar',
        data: {
          labels: targets.map(t => t.target),
          datasets: [{
            label: 'Footprint Score',
            data: targets.map(t => t.footprint_score || 0),
            backgroundColor: '#9d4edd',
            borderColor: '#c77dff',
            borderWidth: 1
          }]
        },
        options: {
          indexAxis: 'y',
          scales: {
            x: { suggestedMin: 0, suggestedMax: 100,
                 ticks: { color: '#c77dff' },
                 grid:  { color: 'rgba(157,78,221,0.15)' } },
            y: { ticks: { color: '#c77dff' }, grid: { display: false } }
          },
          plugins: {
            legend: { display: false }
          },
          responsive: true, maintainAspectRatio: false
        }
      });
    }
  }
})();
"""


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _badge(severity: str) -> str:
    sev = (severity or "info").lower()
    return f'<span class="badge {html.escape(sev)}">{html.escape(sev)}</span>'


def _value_to_html(v: Any, profile_url: Optional[str] = None) -> str:
    if v is None:
        return '<span class="kvpair">—</span>'
    if isinstance(v, bool):
        return f'<span class="kvpair">{"true" if v else "false"}</span>'
    if isinstance(v, (list, tuple)):
        if not v:
            return '<span class="kvpair">[]</span>'
        if all(isinstance(x, (str, int, float, bool)) for x in v):
            parts: List[str] = []
            for x in v:
                xs = str(x)
                if xs.startswith("http://") or xs.startswith("https://"):
                    parts.append(f'<a href="{html.escape(xs)}" target="_blank" rel="noopener">{html.escape(xs)}</a>')
                else:
                    parts.append(html.escape(xs))
            return "<br>".join(parts)
        return f"<pre>{html.escape(json.dumps(v, indent=2, default=str))}</pre>"
    if isinstance(v, dict):
        return f"<pre>{html.escape(json.dumps(v, indent=2, default=str))}</pre>"
    s = str(v)
    if profile_url and (profile_url.startswith("http://") or profile_url.startswith("https://")):
        return f'<a href="{html.escape(profile_url)}" target="_blank" rel="noopener">{html.escape(s)}</a>'
    if s.startswith("http://") or s.startswith("https://"):
        return f'<a href="{html.escape(s)}" target="_blank" rel="noopener">{html.escape(s)}</a>'
    return html.escape(s)


def _module_section(m: ModuleResult) -> str:
    rows: List[str] = []
    for f in m.findings:
        avatar = ""
        if f.avatar_url:
            avatar = (
                f'<img class="avatar" src="{html.escape(f.avatar_url)}" '
                f'alt="" loading="lazy" onerror="this.style.display=\'none\'">'
            )
        copy_target = ""
        if isinstance(f.value, (str, int, float, bool)) and not isinstance(f.value, bool):
            copy_target = str(f.value)
        elif isinstance(f.value, str):
            copy_target = f.value
        if isinstance(f.value, (list, dict)):
            copy_target = json.dumps(f.value, default=str)
        copy_btn = ""
        if copy_target and len(copy_target) < 1000:
            copy_btn = (
                f'<button class="copy-btn" data-copy="{html.escape(copy_target, quote=True)}">copy</button>'
            )
        rows.append(
            f'<tr>'
            f'<td class="k">{avatar}{html.escape(f.key)}{copy_btn}</td>'
            f'<td class="v">{_value_to_html(f.value, f.profile_url)}</td>'
            f'<td>{_badge(f.severity)}</td>'
            f'<td><span class="kvpair">{html.escape(f.source or "")}</span></td>'
            f'<td><span class="kvpair">{html.escape(f.note or "")}</span></td>'
            f'</tr>'
        )
    if not rows:
        rows.append('<tr><td colspan="5"><span class="kvpair">No findings</span></td></tr>')

    err = ""
    if m.error:
        err = (
            f'<div class="kvpair" style="color:var(--danger);margin:6px 0 12px 0;">'
            f'error: {html.escape(m.error)}</div>'
        )
    summary = (
        f'<div class="module-summary">{html.escape(m.summary)}</div>'
        if m.summary else ""
    )
    return f"""
    <details class="module" open>
      <summary>{html.escape(m.module.upper())} &nbsp;<span class="kvpair">started {html.escape(m.started_at)}</span></summary>
      {summary}
      {err}
      <table class="findings">
        <thead><tr><th>key</th><th>value</th><th>severity</th><th>source</th><th>note</th></tr></thead>
        <tbody>
        {''.join(rows)}
        </tbody>
      </table>
    </details>
    """


def _correlations_section(t: TargetReport) -> str:
    if not t.correlations:
        return ""
    chips: List[str] = []
    for c in t.correlations:
        cls = "corr-link confirmed" if c.confirmed else "corr-link"
        body = (
            f'<span class="ctype">{html.escape(c.derived_type)}</span>'
            f'{html.escape(c.derived_value)}'
            f' <span class="kvpair">[{html.escape(c.confidence)}{" / confirmed" if c.confirmed else ""}]</span>'
        )
        if c.profile_url:
            chips.append(f'<a class="{cls}" href="{html.escape(c.profile_url)}" target="_blank" rel="noopener">{body}</a>')
        else:
            chips.append(f'<span class="{cls}">{body}</span>')
    return f"""
    <div class="correlations">
      <h4>// CORRELATION LINKS</h4>
      {''.join(chips)}
    </div>
    """


def _timeline_section(t: TargetReport) -> str:
    rows: List[str] = []
    for m in t.modules:
        if m.started_at:
            rows.append(
                f'<div class="row"><b>{html.escape(m.started_at)}</b> &nbsp; '
                f'{html.escape(m.module)} &nbsp; '
                f'{html.escape(m.summary or "")}</div>'
            )
    if not rows:
        return ""
    return f"""
    <details class="module">
      <summary>TIMELINE</summary>
      <div class="timeline">{''.join(rows)}</div>
    </details>
    """


def _dating_footprint_section(t: TargetReport) -> str:
    """Render the 💕 Dating Footprint panel for a target.

    Pulls data from the `dating` module and from any dating-breach matches
    surfaced by `email_recon`. Three-state color coding:
        red    -> high stigma (hookup, LGBTQ+) OR confirmed breach hit
        yellow -> mainstream dating / matrimonial
        green  -> chat-adjacent (Telegram, Reddit) + confirmed public profile
    """
    dating_mod: Optional[ModuleResult] = None
    email_mod: Optional[ModuleResult] = None
    for m in t.modules:
        if m.module == "dating":
            dating_mod = m
        elif m.module == "email":
            email_mod = m

    if not dating_mod and not (email_mod and email_mod.data.get("dating_breach_hits")):
        return ""

    # ---- Tile data ----
    by_cat: Dict[str, List[Dict[str, Any]]] = (dating_mod.data.get("search_urls") if dating_mod else {}) or {}
    public_profiles: Dict[str, Any] = (dating_mod.data.get("public_profiles") if dating_mod else {}) or {}
    breach_hits: List[str] = (email_mod.data.get("dating_breach_hits") if email_mod else []) or []

    cat_meta = [
        ("hookup",     "high",   "Hookup / Casual"),
        ("lgbtq",      "high",   "LGBTQ+ Networks"),
        ("dating",     "medium", "Mainstream Dating"),
        ("matrimonial","medium", "Matrimonial"),
        ("chat",       "low",    "Chat-Adjacent"),
    ]

    panels: List[str] = []
    total_links = 0

    # ---- Confirmed public-profile hits (green) ----
    confirmed_tiles: List[str] = []
    tg = public_profiles.get("telegram") or {}
    if tg.get("exists"):
        url = html.escape(tg.get("url") or "")
        name = html.escape(tg.get("display_name") or "")
        confirmed_tiles.append(
            f'<a class="dt confirmed" href="{url}" target="_blank" rel="noopener">'
            f'<span class="dt-icon">✓</span>'
            f'<span class="dt-body"><b>Telegram</b><span class="dt-sub">{name or "public handle exists"}</span></span>'
            f'</a>'
        )
    rd = public_profiles.get("reddit") or {}
    if rd.get("exists"):
        url = html.escape(rd.get("url") or "")
        karma = (rd.get("comment_karma") or 0) + (rd.get("link_karma") or 0)
        confirmed_tiles.append(
            f'<a class="dt confirmed" href="{url}" target="_blank" rel="noopener">'
            f'<span class="dt-icon">✓</span>'
            f'<span class="dt-body"><b>Reddit</b><span class="dt-sub">karma {karma}</span></span>'
            f'</a>'
        )
    wa = public_profiles.get("whatsapp") or {}
    if wa.get("reachable"):
        url = html.escape(wa.get("url") or "")
        confirmed_tiles.append(
            f'<a class="dt confirmed" href="{url}" target="_blank" rel="noopener">'
            f'<span class="dt-icon">✓</span>'
            f'<span class="dt-body"><b>WhatsApp</b><span class="dt-sub">wa.me reachable</span></span>'
            f'</a>'
        )
    if confirmed_tiles:
        panels.append(
            '<div class="dt-group">'
            '<h5 class="dt-group-title low">// CONFIRMED PUBLIC PRESENCE</h5>'
            f'<div class="dt-grid">{"".join(confirmed_tiles)}</div>'
            '</div>'
        )

    # ---- Breach match panel (red) ----
    if breach_hits:
        chips = "".join(
            f'<span class="dt-breach-chip">{html.escape(b)}</span>'
            for b in breach_hits[:20]
        )
        panels.append(
            '<div class="dt-group">'
            '<h5 class="dt-group-title high">// DATING / ADULT BREACH MATCHES</h5>'
            '<div class="dt-breach">'
            '<div class="dt-breach-note">Email present in known dating/adult breach corpora '
            '(public breach data via HIBP / LeakCheck). This is a strong real-world signal — '
            'not an account-enumeration claim.</div>'
            f'<div class="dt-breach-chips">{chips}</div>'
            '</div>'
            '</div>'
        )

    # ---- Curated review URL tiles per category ----
    for cat_key, tier, title in cat_meta:
        items = by_cat.get(cat_key) or []
        if not items:
            continue
        tiles = []
        for it in items:
            url = html.escape(it.get("url") or "")
            name = html.escape(it.get("platform") or "")
            tiles.append(
                f'<a class="dt {tier}" href="{url}" target="_blank" rel="noopener">'
                f'<span class="dt-icon">?</span>'
                f'<span class="dt-body"><b>{name}</b><span class="dt-sub">manual review</span></span>'
                f'</a>'
            )
        total_links += len(tiles)
        panels.append(
            f'<div class="dt-group">'
            f'<h5 class="dt-group-title {tier}">// {html.escape(title.upper())}'
            f' <span class="dt-count">({len(tiles)})</span></h5>'
            f'<div class="dt-grid">{"".join(tiles)}</div>'
            f'</div>'
        )

    if not panels:
        return ""

    legend = (
        '<div class="dt-legend">'
        '<span class="dt-leg low">● confirmed public</span>'
        '<span class="dt-leg medium">● mainstream</span>'
        '<span class="dt-leg high">● high-stigma / breach</span>'
        '</div>'
    )

    return f"""
    <details class="dt-section" open>
      <summary class="dt-summary">
        <span class="dt-title">💕 DATING FOOTPRINT</span>
        <span class="dt-count-summary">
          {len(breach_hits)} breach hit(s) · {sum(1 for v in public_profiles.values() if isinstance(v, dict) and (v.get("exists") or v.get("reachable")))} public profile(s) · {total_links} review link(s)
        </span>
      </summary>
      {legend}
      {''.join(panels)}
    </details>
    """


def _target_section(t: TargetReport) -> str:
    risk = t.risk_level()
    score = t.footprint_score()
    modules_html = "".join(
        _module_section(m) for m in t.modules
        if m.module not in ("correlation", "dating")
    )
    corr_module_html = "".join(_module_section(m) for m in t.modules if m.module == "correlation")
    return f"""
    <details class="target" id="target-{html.escape(t.target)}" open>
      <summary>
        <span class="title">{html.escape(t.target)}<span class="type">[{html.escape(t.target_type)}]</span></span>
        <span>
          <span class="score-num">{score}/100</span>
          <span class="score-bar"><span style="width:{score}%"></span></span>
          {_badge(risk)}
        </span>
      </summary>
      {modules_html}
      {corr_module_html}
      {_correlations_section(t)}
      {_dating_footprint_section(t)}
      {_timeline_section(t)}
    </details>
    """


def _exec_summary(inv: Investigation) -> str:
    s = inv.summary or {}
    sev = s.get("severity_breakdown", {})
    risk_breakdown = s.get("risk_breakdown", {})
    risks_html = "".join(
        f'<div class="card"><div class="label">{html.escape(k)} risk targets</div><div class="value">{v}</div></div>'
        for k, v in sorted(risk_breakdown.items(), key=lambda kv: kv[0])
    )
    return f"""
    <section class="exec">
      <h2>// EXECUTIVE SUMMARY</h2>
      <div class="cards">
        <div class="card"><div class="label">targets</div><div class="value">{s.get("total_targets", 0)}</div></div>
        <div class="card"><div class="label">findings</div><div class="value">{s.get("total_findings", 0)}</div></div>
        <div class="card"><div class="label">avg footprint</div><div class="value">{s.get("avg_footprint_score", 0)}/100</div></div>
        <div class="card"><div class="label">correlations</div><div class="value">{s.get("total_correlations", 0)}</div></div>
        <div class="card"><div class="label">critical</div><div class="value">{sev.get("critical", 0)}</div></div>
        <div class="card"><div class="label">high</div><div class="value">{sev.get("high", 0)}</div></div>
        <div class="card"><div class="label">medium</div><div class="value">{sev.get("medium", 0)}</div></div>
        {risks_html}
      </div>
    </section>
    """


def _sidebar(inv: Investigation) -> str:
    items = []
    for t in inv.targets:
        score = t.footprint_score()
        items.append(
            f'<a class="nav-item" href="#target-{html.escape(t.target)}">'
            f'{html.escape(t.target)}<span class="type">[{html.escape(t.target_type)}]</span>'
            f'<span class="score">{score}</span>'
            f'</a>'
        )
    return f"""
    <aside class="sidebar">
      <h2>// EXO-OSINT</h2>
      <div>{''.join(items) or '<div class="kvpair">no targets</div>'}</div>
      <div class="toolbox">
        <button class="tool-btn" id="btn-theme">☾ toggle theme</button>
        <button class="tool-btn" id="btn-export-json">⬇ export JSON</button>
        <button class="tool-btn" id="btn-export-csv">⬇ export CSV</button>
      </div>
    </aside>
    """


BANNER_TXT = """\
███████╗██╗  ██╗ ██████╗        ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔════╝╚██╗██╔╝██╔═══██╗      ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
█████╗   ╚███╔╝ ██║   ██║█████╗██║   ██║███████╗██║██╔██╗ ██║   ██║   
██╔══╝   ██╔██╗ ██║   ██║╚════╝██║   ██║╚════██║██║██║╚██╗██║   ██║   
███████╗██╔╝ ██╗╚██████╔╝      ╚██████╔╝███████║██║██║ ╚████║   ██║   
╚══════╝╚═╝  ╚═╝ ╚═════╝        ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝"""


def _safe_json_for_script(payload: Dict[str, Any]) -> str:
    """Serialize JSON for safe embedding inside <script> tags."""
    s = json.dumps(payload, default=str, ensure_ascii=False)
    return s.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def write_html(investigation: Investigation, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    summary_html = _exec_summary(investigation)
    sidebar_html = _sidebar(investigation)
    targets_html = "".join(_target_section(t) for t in investigation.targets)
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    embedded = _safe_json_for_script(investigation.to_dict())

    html_doc = f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EXO-OSINT Report &middot; {html.escape(generated)}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>{CSS}</style>
</head>
<body>
<div class="layout">
  {sidebar_html}
  <main class="content">
    <header class="banner">
      <pre>{html.escape(BANNER_TXT)}</pre>
      <div class="tagline">[ Open Source Intelligence Framework ]</div>
      <div class="subtag">// Authorized intelligence gathering only</div>
      <div class="meta">
        <span>v{html.escape(investigation.version)}</span>
        <span>generated {html.escape(generated)}</span>
        <span>started {html.escape(investigation.started_at)}</span>
        <span>finished {html.escape(investigation.finished_at)}</span>
      </div>
    </header>

    {summary_html}

    <div class="dashboard-row">
      <div class="panel">
        <h3>// GEOLOCATION MAP</h3>
        <div id="map"></div>
      </div>
      <div class="panel">
        <h3>// SEVERITY DISTRIBUTION</h3>
        <div class="chart-wrapper"><canvas id="sev-chart"></canvas></div>
      </div>
    </div>

    <div class="dashboard-row" style="grid-template-columns: 1fr;">
      <div class="panel">
        <h3>// FOOTPRINT SCORE PER TARGET</h3>
        <div class="chart-wrapper"><canvas id="fp-chart"></canvas></div>
      </div>
    </div>

    {targets_html}

    <footer class="foot">
      EXO-OSINT v{html.escape(investigation.version)} &middot; rendered {html.escape(generated)} &middot;
      authorized intelligence gathering only
    </footer>
  </main>
</div>

<script id="exo-data" type="application/json">{embedded}</script>
<script>{JS}</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return path
