"""Professional reports — HTML (ghost/phantom theme), JSON, CSV."""

from __future__ import annotations

import csv
import html
import json
import os
from datetime import datetime
from typing import Any, Dict, List

from .types import Investigation, ModuleResult, TargetReport


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def write_json(investigation: Investigation, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(investigation.to_dict(), f, indent=2, default=str)
    return path


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def write_csv(investigation: Investigation, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["target", "target_type", "module", "key", "value", "severity", "source", "note"])
        for t in investigation.targets:
            for m in t.modules:
                if not m.findings:
                    w.writerow([t.target, t.target_type, m.module, "", "", "info", "", "no findings"])
                for finding in m.findings:
                    val = finding.value
                    if isinstance(val, (list, dict)):
                        val = json.dumps(val, default=str, ensure_ascii=False)
                    w.writerow([
                        t.target, t.target_type, m.module,
                        finding.key, val, finding.severity, finding.source, finding.note,
                    ])
    return path


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

CSS = """
:root {
  --bg: #0a0a0f;
  --bg2: #12121a;
  --bg3: #1a1a26;
  --primary: #9d4edd;
  --accent: #c77dff;
  --text: #e0e0e0;
  --text-dim: #9b9bad;
  --danger: #ff4d6d;
  --success: #06d6a0;
  --warning: #ffd166;
  --border: #2a1a3a;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg);
  color: var(--text);
  font-family: 'Share Tech Mono', 'Courier New', monospace;
  min-height: 100vh;
}
body {
  background:
    radial-gradient(ellipse at top left, rgba(157,78,221,0.12), transparent 40%),
    radial-gradient(ellipse at bottom right, rgba(199,125,255,0.08), transparent 50%),
    var(--bg);
}
.container { max-width: 1200px; margin: 0 auto; padding: 32px 20px 80px; }

header.banner {
  text-align: center;
  padding: 28px 16px;
  border: 1px solid var(--primary);
  border-radius: 8px;
  background: linear-gradient(180deg, rgba(157,78,221,0.10), rgba(157,78,221,0.02));
  box-shadow: 0 0 40px rgba(157,78,221,0.25), inset 0 0 30px rgba(157,78,221,0.05);
  margin-bottom: 28px;
}
header.banner h1 {
  margin: 0 0 8px 0;
  font-size: 2.4rem;
  letter-spacing: 6px;
  color: var(--accent);
  text-shadow: 0 0 14px rgba(199,125,255,0.7);
}
header.banner .tagline {
  color: var(--accent);
  font-size: 0.95rem;
  letter-spacing: 2px;
}
header.banner .subtag {
  color: var(--text-dim);
  font-size: 0.8rem;
  margin-top: 6px;
}
header.banner .meta {
  margin-top: 14px;
  display: flex; flex-wrap: wrap; gap: 10px; justify-content: center;
  font-size: 0.8rem;
  color: var(--text-dim);
}

section.exec {
  margin: 24px 0;
  padding: 20px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg2);
  box-shadow: 0 0 20px rgba(157,78,221,0.08);
}
section.exec h2 {
  color: var(--accent);
  margin: 0 0 14px 0;
  font-size: 1.2rem;
  letter-spacing: 2px;
  text-shadow: 0 0 6px rgba(199,125,255,0.5);
}
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 14px; }
.card {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px;
  background: var(--bg3);
}
.card .label { color: var(--text-dim); font-size: 0.75rem; letter-spacing: 1px; text-transform: uppercase; }
.card .value { color: var(--accent); font-size: 1.6rem; margin-top: 6px; text-shadow: 0 0 6px rgba(199,125,255,0.4); }

.target {
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 22px;
  background: var(--bg2);
  overflow: hidden;
}
.target > summary {
  list-style: none;
  cursor: pointer;
  padding: 16px 20px;
  background: linear-gradient(90deg, rgba(157,78,221,0.18), rgba(157,78,221,0.03));
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  flex-wrap: wrap;
}
.target > summary::-webkit-details-marker { display: none; }
.target > summary .title { color: var(--accent); font-size: 1.1rem; letter-spacing: 1px; }
.target > summary .title .type { color: var(--text-dim); font-size: 0.8rem; margin-left: 8px; }

.module { padding: 16px 20px; border-top: 1px dashed var(--border); }
.module:first-of-type { border-top: none; }
.module > summary {
  list-style: none;
  cursor: pointer;
  padding: 8px 0;
  color: var(--accent);
  letter-spacing: 1px;
}
.module > summary::-webkit-details-marker { display: none; }
.module > summary::before { content: "▸ "; color: var(--primary); }
.module[open] > summary::before { content: "▾ "; }

table.findings { width: 100%; border-collapse: collapse; margin-top: 8px; }
table.findings th, table.findings td {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  font-size: 0.88rem;
  word-break: break-word;
}
table.findings th { color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; font-size: 0.72rem; }
table.findings td.k { color: var(--accent); white-space: nowrap; }
table.findings td.v { color: var(--text); }
table.findings td pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: inherit;
  color: var(--text);
}

.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 0.72rem;
  letter-spacing: 1px;
  text-transform: uppercase;
  border: 1px solid var(--primary);
  color: var(--accent);
  background: rgba(157,78,221,0.10);
  box-shadow: 0 0 8px rgba(157,78,221,0.35);
}
.badge.info { border-color: var(--primary); color: var(--accent); }
.badge.low { border-color: var(--success); color: var(--success); box-shadow: 0 0 8px rgba(6,214,160,0.35); }
.badge.medium { border-color: var(--warning); color: var(--warning); box-shadow: 0 0 8px rgba(255,209,102,0.35); }
.badge.high { border-color: var(--danger); color: var(--danger); box-shadow: 0 0 8px rgba(255,77,109,0.45); }
.badge.critical { border-color: var(--danger); color: #fff; background: var(--danger); box-shadow: 0 0 14px var(--danger); }

.kvpair { color: var(--text-dim); font-size: 0.8rem; }
footer.foot {
  margin-top: 40px;
  text-align: center;
  color: var(--text-dim);
  font-size: 0.8rem;
  border-top: 1px solid var(--border);
  padding-top: 18px;
}
"""


def _badge(severity: str) -> str:
    sev = (severity or "info").lower()
    return f'<span class="badge {sev}">{html.escape(sev)}</span>'


def _value_to_html(v: Any) -> str:
    if v is None:
        return '<span class="kvpair">—</span>'
    if isinstance(v, bool):
        return f'<span class="kvpair">{"true" if v else "false"}</span>'
    if isinstance(v, (list, tuple)):
        if not v:
            return '<span class="kvpair">[]</span>'
        if all(isinstance(x, (str, int, float, bool)) for x in v):
            return "<br>".join(html.escape(str(x)) for x in v)
        return f"<pre>{html.escape(json.dumps(v, indent=2, default=str))}</pre>"
    if isinstance(v, dict):
        return f"<pre>{html.escape(json.dumps(v, indent=2, default=str))}</pre>"
    return html.escape(str(v))


def _module_section(m: ModuleResult) -> str:
    rows: List[str] = []
    for f in m.findings:
        rows.append(
            f'<tr>'
            f'<td class="k">{html.escape(f.key)}</td>'
            f'<td class="v">{_value_to_html(f.value)}</td>'
            f'<td>{_badge(f.severity)}</td>'
            f'<td><span class="kvpair">{html.escape(f.source or "")}</span></td>'
            f'<td><span class="kvpair">{html.escape(f.note or "")}</span></td>'
            f'</tr>'
        )
    if not rows:
        rows.append('<tr><td colspan="5"><span class="kvpair">No findings</span></td></tr>')

    err = ""
    if m.error:
        err = f'<div class="kvpair" style="color:var(--danger);margin:6px 0 12px 0;">error: {html.escape(m.error)}</div>'

    return f"""
    <details class="module" open>
      <summary>{html.escape(m.module.upper())} &nbsp;<span class="kvpair">started {html.escape(m.started_at)}</span></summary>
      {err}
      <table class="findings">
        <thead><tr><th>key</th><th>value</th><th>severity</th><th>source</th><th>note</th></tr></thead>
        <tbody>
        {''.join(rows)}
        </tbody>
      </table>
    </details>
    """


def _target_section(t: TargetReport) -> str:
    risk = t.risk_level()
    modules_html = "".join(_module_section(m) for m in t.modules)
    return f"""
    <details class="target" open>
      <summary>
        <span class="title">{html.escape(t.target)}<span class="type">[{html.escape(t.target_type)}]</span></span>
        <span>{_badge(risk)}</span>
      </summary>
      {modules_html}
    </details>
    """


def _exec_summary(inv: Investigation) -> str:
    s = inv.summary or {}
    risk_breakdown = s.get("risk_breakdown", {})
    risks_html = "".join(
        f'<div class="card"><div class="label">{html.escape(k)}</div><div class="value">{v}</div></div>'
        for k, v in sorted(risk_breakdown.items())
    ) or '<div class="card"><div class="label">risk</div><div class="value">—</div></div>'
    return f"""
    <section class="exec">
      <h2>// EXECUTIVE SUMMARY</h2>
      <div class="cards">
        <div class="card"><div class="label">targets</div><div class="value">{s.get("total_targets", 0)}</div></div>
        <div class="card"><div class="label">findings</div><div class="value">{s.get("total_findings", 0)}</div></div>
        {risks_html}
      </div>
    </section>
    """


BANNER_HTML = """\
███████╗██╗  ██╗ ██████╗        ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔════╝╚██╗██╔╝██╔═══██╗      ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
█████╗   ╚███╔╝ ██║   ██║█████╗██║   ██║███████╗██║██╔██╗ ██║   ██║   
██╔══╝   ██╔██╗ ██║   ██║╚════╝██║   ██║╚════██║██║██║╚██╗██║   ██║   
███████╗██╔╝ ██╗╚██████╔╝      ╚██████╔╝███████║██║██║ ╚████║   ██║   
╚══════╝╚═╝  ╚═╝ ╚═════╝        ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝"""


def write_html(investigation: Investigation, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    targets_html = "".join(_target_section(t) for t in investigation.targets)
    summary_html = _exec_summary(investigation)
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EXO-OSINT Report</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>
<div class="container">
  <header class="banner">
    <pre style="color:var(--accent);text-shadow:0 0 12px rgba(199,125,255,0.55);text-align:left;display:inline-block;margin:0 0 10px 0;font-size:0.7rem;line-height:1;overflow-x:auto;">{html.escape(BANNER_HTML)}</pre>
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

  {targets_html}

  <footer class="foot">
    EXO-OSINT v{html.escape(investigation.version)} &middot; report rendered {html.escape(generated)} &middot;
    use responsibly &middot; authorized intelligence gathering only
  </footer>
</div>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return path


# ---------------------------------------------------------------------------
# Plain-text "table" stdout output
# ---------------------------------------------------------------------------

def render_text(investigation: Investigation) -> str:
    out: List[str] = []
    out.append("=" * 78)
    out.append("EXO-OSINT REPORT")
    out.append("=" * 78)
    s = investigation.summary or {}
    out.append(f"targets: {s.get('total_targets', 0)} | findings: {s.get('total_findings', 0)}")
    out.append(f"risk: {s.get('risk_breakdown', {})}")
    for t in investigation.targets:
        out.append("")
        out.append("-" * 78)
        out.append(f"TARGET: {t.target}  [{t.target_type}]  risk={t.risk_level()}")
        out.append("-" * 78)
        for m in t.modules:
            out.append(f"  [{m.module}] success={m.success} error={m.error or '-'}")
            for f in m.findings:
                val = f.value
                if isinstance(val, (list, dict)):
                    val = json.dumps(val, default=str)
                val_str = str(val)
                if len(val_str) > 200:
                    val_str = val_str[:200] + "…"
                out.append(f"    - {f.key:24s} [{f.severity:8s}] {val_str}")
    return "\n".join(out)
