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
/* ============================================================
   EXO-OSINT cyberpunk theme
   palette:
     bg     #000000
     primary (neon green)   #00ff41   glow 0 0 8px #00ff41
     header (cyan)          #00cfff   glow 0 0 8px #00cfff
     danger (red)           #ff003c   glow 0 0 8px #ff003c
     warning                #ffe600
     table border           #1a1a1a
     table header bg        #0d0d0d
     card bg                #0a0a0a
   ============================================================ */
:root[data-theme="dark"] {
  --bg: #000000;
  --bg2: #0a0a0a;
  --bg3: #0d0d0d;
  --bg4: #111111;
  --card-bg: #0a0a0a;
  --table-header-bg: #0d0d0d;
  --table-border: #1a1a1a;

  --primary: #00ff41;          /* neon green */
  --primary-glow: 0 0 8px #00ff41;
  --accent: #00ff41;
  --accent-bright: #39ff7a;

  --header: #00cfff;            /* cyan */
  --header-glow: 0 0 8px #00cfff;

  --text: #00ff41;
  --text-dim: #5a8c5a;

  --danger: #ff003c;            /* red */
  --danger-glow: 0 0 8px #ff003c;
  --warning: #ffe600;            /* yellow */
  --warning-glow: 0 0 8px #ffe600;
  --orange: #ff6600;
  --orange-glow: 0 0 8px #ff6600;
  --success: #00ff41;
  --grey: #444444;

  --border: #1a1a1a;
  --shadow: rgba(0,255,65,0.25);
}
:root[data-theme="light"] {
  --bg: #f5f5f5;
  --bg2: #ffffff;
  --bg3: #f0f0f0;
  --bg4: #e8e8e8;
  --card-bg: #ffffff;
  --table-header-bg: #f0f0f0;
  --table-border: #d0d0d0;

  --primary: #007a1f;
  --primary-glow: 0 0 4px rgba(0,122,31,0.4);
  --accent: #007a1f;
  --accent-bright: #00a82a;

  --header: #006c8c;
  --header-glow: 0 0 4px rgba(0,108,140,0.3);

  --text: #1a1a1a;
  --text-dim: #555555;

  --danger: #c8001f;
  --danger-glow: 0 0 4px rgba(200,0,31,0.4);
  --warning: #b08a00;
  --warning-glow: 0 0 4px rgba(176,138,0,0.4);
  --orange: #cc5200;
  --orange-glow: 0 0 4px rgba(204,82,0,0.4);
  --success: #007a1f;
  --grey: #888888;

  --border: #d0d0d0;
  --shadow: rgba(0,122,31,0.15);
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
    radial-gradient(ellipse at top left, rgba(0,255,65,0.08), transparent 40%),
    radial-gradient(ellipse at bottom right, rgba(0,207,255,0.05), transparent 50%),
    var(--bg);
}

/* Layout */
.layout { display: flex; min-height: 100vh; }
aside.sidebar {
  width: 260px;
  flex-shrink: 0;
  background: #000000;
  border-right: 1px solid var(--primary);
  box-shadow: inset -1px 0 8px rgba(0,255,65,0.15);
  padding: 22px 12px;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
}
aside.sidebar h2 {
  color: var(--header);
  text-shadow: var(--header-glow);
  letter-spacing: 3px;
  font-size: 0.95rem;
  margin: 0 0 18px 0;
  padding: 0 8px;
}
aside.sidebar .nav-item {
  display: block;
  padding: 8px 10px;
  margin: 2px 0;
  border-radius: 0;
  color: var(--text);
  text-decoration: none;
  border: 1px solid transparent;
  border-left: 2px solid var(--primary);
  font-size: 0.84rem;
  transition: all .15s;
  word-break: break-all;
}
aside.sidebar .nav-item:hover {
  background: var(--bg3);
  border: 1px solid var(--primary);
  border-left: 2px solid var(--primary);
  color: var(--primary);
  text-shadow: var(--primary-glow);
}
aside.sidebar .nav-item .type {
  color: var(--text-dim);
  font-size: 0.7rem;
  margin-left: 4px;
}
aside.sidebar .nav-item .score {
  float: right;
  background: #000;
  border: 1px solid var(--primary);
  padding: 1px 6px;
  border-radius: 999px;
  font-size: 0.7rem;
  color: var(--primary);
}
aside.sidebar .toolbox {
  margin-top: 18px;
  padding: 10px;
  border-top: 1px dashed var(--primary);
}
aside.sidebar .tool-btn {
  display: block;
  width: 100%;
  margin: 6px 0;
  padding: 8px;
  background: #000;
  border: 1px solid var(--primary);
  border-radius: 0;
  color: var(--primary);
  font-family: inherit;
  font-size: 0.78rem;
  cursor: pointer;
  letter-spacing: 1px;
  text-shadow: var(--primary-glow);
  transition: all .15s;
}
aside.sidebar .tool-btn:hover {
  background: var(--primary);
  color: #000;
  text-shadow: none;
  box-shadow: var(--primary-glow);
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
  border-radius: 0;
  background: #000;
  box-shadow: 0 0 24px var(--shadow), inset 0 0 30px rgba(0,255,65,0.05);
  margin-bottom: 24px;
  position: relative;
  overflow: hidden;
}
header.banner::before {
  content: "";
  position: absolute; top: 0; left: -100%;
  width: 30%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(0,255,65,0.18), transparent);
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
  color: var(--primary);
  text-shadow: var(--primary-glow);
  overflow-x: auto;
}
header.banner h1.report-title {
  color: var(--header);
  text-shadow: var(--header-glow);
  letter-spacing: 4px;
  font-size: 1.4rem;
  margin: 8px 0 4px 0;
}
header.banner .tagline {
  color: var(--header);
  text-shadow: var(--header-glow);
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
  font-size: 0.78rem;
  color: var(--primary);
  letter-spacing: 1px;
}
header.banner .auth-warning {
  margin-top: 12px;
  background: #0d0000;
  border-left: 3px solid var(--danger);
  color: var(--danger);
  text-shadow: var(--danger-glow);
  padding: 12px 16px;
  letter-spacing: 1px;
  font-size: 0.78rem;
  text-align: left;
  display: inline-block;
}

/* Cards */
section.exec {
  margin: 18px 0 24px 0;
  padding: 20px;
  border: 1px solid var(--primary);
  border-radius: 0;
  background: var(--card-bg);
  box-shadow: 0 0 18px var(--shadow);
}
section.exec h2 {
  color: var(--header);
  margin: 0 0 14px 0;
  font-size: 1.1rem;
  letter-spacing: 2px;
  text-shadow: var(--header-glow);
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px,1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.card {
  border: 1px solid var(--primary);
  border-radius: 0;
  padding: 12px 14px;
  background: var(--card-bg);
  box-shadow: inset 0 0 8px rgba(0,255,65,0.05);
}
.card .label {
  color: var(--header);
  font-size: 0.72rem;
  letter-spacing: 1px;
  text-transform: uppercase;
}
.card .value {
  color: var(--primary);
  font-size: 1.5rem;
  margin-top: 4px;
  text-shadow: var(--primary-glow);
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
  border: 1px solid var(--primary);
  background: var(--card-bg);
  border-radius: 0;
  padding: 14px 16px;
  min-height: 240px;
  box-shadow: 0 0 12px var(--shadow);
}
.panel h3 {
  color: var(--header);
  font-size: 0.9rem;
  letter-spacing: 2px;
  margin: 0 0 10px 0;
  text-shadow: var(--header-glow);
}
#map { height: 340px; border-radius: 0; background: #000; border: 1px solid var(--primary); }
.chart-wrapper { height: 340px; position: relative; }

/* Targets */
.target {
  border: 1px solid var(--primary);
  border-radius: 0;
  margin-bottom: 22px;
  background: var(--card-bg);
  overflow: hidden;
  scroll-margin-top: 8px;
  box-shadow: 0 0 12px var(--shadow);
}
.target > summary {
  list-style: none;
  cursor: pointer;
  padding: 14px 18px;
  background: linear-gradient(90deg, rgba(0,255,65,0.10), rgba(0,255,65,0.02));
  border-bottom: 1px solid var(--primary);
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  flex-wrap: wrap;
}
.target > summary::-webkit-details-marker { display: none; }
.target > summary .title {
  color: var(--header);
  font-size: 1.05rem;
  letter-spacing: 1px;
  text-shadow: var(--header-glow);
}
.target > summary .title .type {
  color: var(--text-dim);
  font-size: 0.78rem;
  margin-left: 8px;
}
.score-bar {
  display: inline-block;
  width: 110px; height: 8px;
  background: #000;
  border: 1px solid var(--primary);
  border-radius: 4px; overflow: hidden;
  vertical-align: middle;
  margin-right: 8px;
}
.score-bar > span {
  display: block; height: 100%;
  background: linear-gradient(90deg, var(--primary), var(--warning) 60%, var(--danger));
  box-shadow: 0 0 6px var(--primary);
}
.score-num { color: var(--primary); margin-right: 6px; text-shadow: var(--primary-glow); }

.module {
  padding: 14px 18px;
  border-top: 1px dashed var(--primary);
}
.module:first-of-type { border-top: none; }
.module > summary {
  list-style: none;
  cursor: pointer;
  padding: 6px 0;
  color: var(--header);
  letter-spacing: 1px;
  text-shadow: var(--header-glow);
}
.module > summary::-webkit-details-marker { display: none; }
.module > summary::before { content: "▸ "; color: var(--primary); }
.module[open] > summary::before { content: "▾ "; color: var(--primary); }
.module .module-summary {
  color: var(--text-dim);
  font-size: 0.78rem;
  font-style: italic;
  margin: 4px 0 8px 0;
}

/* Findings table */
table.findings { width: 100%; border-collapse: collapse; margin-top: 8px; background: #000; }
table.findings th, table.findings td {
  text-align: left;
  padding: 7px 9px;
  border: 1px solid var(--table-border);
  vertical-align: top;
  font-size: 0.85rem;
  word-break: break-word;
}
table.findings th {
  background: var(--table-header-bg);
  color: var(--header);
  text-shadow: var(--header-glow);
  text-transform: uppercase;
  letter-spacing: 1px;
  font-size: 0.7rem;
  border: 1px solid var(--table-border);
}
table.findings td { color: var(--primary); border: 1px solid #111; }
table.findings tr.found td, table.findings tr.open td { color: var(--primary); font-weight: bold; text-shadow: var(--primary-glow); }
table.findings tr.notfound td, table.findings tr.closed td { color: var(--danger); }
table.findings td.k { color: var(--header); white-space: nowrap; text-shadow: var(--header-glow); }
table.findings td.v { color: var(--primary); }
table.findings td pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: inherit;
  color: var(--primary);
}
table.findings td a {
  color: var(--header);
  text-decoration: none;
  border-bottom: 1px dashed var(--header);
}
table.findings td a:hover { color: var(--primary); border-bottom-color: var(--primary); }

img.avatar {
  width: 28px; height: 28px;
  border-radius: 50%;
  vertical-align: middle;
  margin-right: 6px;
  border: 1px solid var(--primary);
}
img.screenshot {
  max-width: 220px;
  border: 1px solid var(--primary);
  border-radius: 0;
  margin-top: 4px;
}

.copy-btn {
  cursor: pointer;
  background: #000;
  border: 1px solid var(--primary);
  color: var(--primary);
  font-family: inherit;
  font-size: 0.7rem;
  padding: 1px 6px;
  border-radius: 0;
  margin-left: 6px;
  opacity: 0.65;
  transition: all .15s;
}
.copy-btn:hover {
  opacity: 1;
  background: var(--primary);
  color: #000;
  box-shadow: var(--primary-glow);
}

/* Command-style code blocks (used inline anywhere a CLI command appears) */
pre.cmd, code.cmd, .command-block {
  background: #0a0a0a;
  border: 1px solid rgba(0,255,65,0.2);   /* #00ff4133 */
  border-left: 3px solid var(--primary);
  color: var(--primary);
  font-family: 'Share Tech Mono', monospace;
  padding: 8px 12px;
  margin: 6px 0;
  display: block;
  white-space: pre-wrap;
  word-break: break-word;
  text-shadow: var(--primary-glow);
}

/* Warning box */
.warning-box {
  background: #0d0000;
  border-left: 3px solid var(--danger);
  color: var(--danger);
  text-shadow: var(--danger-glow);
  padding: 12px 16px;
  letter-spacing: 1px;
  margin: 8px 0;
}

/* Severity / risk badges -- cyberpunk glows */
.badge {
  display: inline-block;
  padding: 2px 9px;
  border-radius: 0;
  font-size: 0.68rem;
  letter-spacing: 1px;
  text-transform: uppercase;
  border: 1px solid var(--primary);
  color: var(--primary);
  background: #000;
  text-shadow: var(--primary-glow);
  box-shadow: var(--primary-glow);
}
.badge.info       { border-color: var(--primary); color: var(--primary); text-shadow: var(--primary-glow); box-shadow: var(--primary-glow); }
.badge.low        { border-color: var(--header);  color: var(--header);  text-shadow: var(--header-glow);  box-shadow: var(--header-glow);  }
.badge.medium     { border-color: var(--warning); color: var(--warning); text-shadow: var(--warning-glow); box-shadow: var(--warning-glow); }
.badge.high       { border-color: var(--orange);  color: var(--orange);  text-shadow: var(--orange-glow);  box-shadow: var(--orange-glow);  }
.badge.critical   { border-color: var(--danger);  color: var(--danger);  text-shadow: var(--danger-glow);  box-shadow: var(--danger-glow);  }

/* Found / not-found / unknown / blocked badges */
.badge.found      { border-color: var(--primary); color: var(--primary); text-shadow: var(--primary-glow); box-shadow: var(--primary-glow); }
.badge.notfound,
.badge.not-found  { border-color: var(--danger);  color: var(--danger);  text-shadow: var(--danger-glow);  box-shadow: var(--danger-glow);  }
.badge.unknown    { border-color: var(--warning); color: var(--warning); text-shadow: var(--warning-glow); box-shadow: var(--warning-glow); }
.badge.blocked    { border-color: var(--grey);    color: var(--grey);    text-shadow: none;                box-shadow: none; }

.kvpair { color: var(--text-dim); font-size: 0.8rem; }

/* Correlation panel */
.correlations {
  padding: 12px 18px 18px 18px;
  border-top: 2px solid var(--primary);
  background: var(--card-bg);
}
.correlations h4 {
  color: var(--header);
  font-size: 0.9rem;
  letter-spacing: 1px;
  margin: 0 0 10px 0;
  text-shadow: var(--header-glow);
}
.corr-link {
  display: inline-block;
  margin: 4px 6px 4px 0;
  padding: 6px 10px;
  border: 1px solid var(--primary);
  border-radius: 0;
  background: #000;
  font-size: 0.78rem;
  color: var(--primary);
  text-decoration: none;
}
.corr-link.confirmed {
  border-color: var(--primary);
  color: var(--primary);
  text-shadow: var(--primary-glow);
  box-shadow: var(--primary-glow);
}
.corr-link .ctype {
  color: var(--header);
  font-size: 0.7rem;
  text-transform: uppercase;
  margin-right: 6px;
  text-shadow: var(--header-glow);
}

/* Timeline */
.timeline {
  margin-top: 10px;
  padding: 8px 14px 8px 30px;
  border-left: 2px dashed var(--primary);
  font-size: 0.78rem;
}
.timeline .row { color: var(--text-dim); margin: 3px 0; }
.timeline .row b { color: var(--primary); text-shadow: var(--primary-glow); }

footer.foot {
  margin-top: 36px;
  text-align: center;
  color: var(--text-dim);
  font-size: 0.78rem;
  border-top: 1px solid var(--primary);
  padding-top: 18px;
}

@media (max-width: 800px) {
  .layout { flex-direction: column; }
  aside.sidebar { width: 100%; height: auto; position: static; border-right: none; border-bottom: 1px solid var(--primary); }
  main.content { padding: 18px; }
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
      L.circleMarker([20, 0], {
        radius: 9, color: '#00ff41', fillColor: '#00ff41',
        fillOpacity: 0.7, weight: 2
      }).bindPopup('No IP geolocation in this report').addTo(map);
    } else {
      const group = L.featureGroup();
      points.forEach(p => {
        const m = L.circleMarker([p.lat, p.lon], {
          radius: 9, color: '#00ff41', fillColor: '#00ff41',
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
            // info=green, low=cyan, medium=yellow, high=orange, critical=red
            backgroundColor: ['#00ff41','#00cfff','#ffe600','#ff6600','#ff003c'],
            borderColor: '#000000', borderWidth: 1
          }]
        },
        options: {
          plugins: {
            legend: { position: 'bottom', labels: { color: '#00cfff' } },
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
            backgroundColor: '#00ff41',
            borderColor: '#00cfff',
            borderWidth: 1
          }]
        },
        options: {
          indexAxis: 'y',
          scales: {
            x: { suggestedMin: 0, suggestedMax: 100,
                 ticks: { color: '#00cfff' },
                 grid:  { color: 'rgba(0,255,65,0.15)' } },
            y: { ticks: { color: '#00cfff' }, grid: { display: false } }
          },
          plugins: {
            legend: { display: false, labels: { color: '#00cfff' } }
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


def _target_section(t: TargetReport) -> str:
    risk = t.risk_level()
    score = t.footprint_score()
    modules_html = "".join(
        _module_section(m) for m in t.modules
        if m.module not in ("correlation",)
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

    # Build target list string for header
    target_list = ", ".join(t.target for t in investigation.targets) or "—"

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
      <h1 class="report-title">EXO-OSINT &mdash; Intelligence Report</h1>
      <div class="tagline">[ Open Source Intelligence Framework ]</div>
      <div class="subtag">// Authorized intelligence gathering only</div>
      <div class="meta">
        <span>Generated: {html.escape(generated)}</span>
        <span>&middot;</span>
        <span>Target: {html.escape(target_list)}</span>
        <span>&middot;</span>
        <span>Engine v{html.escape(investigation.version)}</span>
      </div>
      <div class="auth-warning">// AUTHORIZED USE ONLY</div>
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
      // AUTHORIZED USE ONLY
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
