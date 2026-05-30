// Helpers for turning the EXO-OSINT engine's investigation dict into
// UI-friendly shapes and downloadable exports.
//
// The investigation object has the shape produced by
// `exoosint.types.Investigation.to_dict()`:
//
//   {
//     version, started_at, finished_at,
//     summary: { total_findings, total_correlations, avg_footprint_score, ... },
//     targets: [
//       {
//         target, target_type, risk, footprint_score,
//         correlations: [ ... ],
//         modules: [
//           {
//             module, target, target_type, success, error, summary,
//             data: { lat, lon, geo: { city, regionName, country, isp, org, ... }, ... },
//             findings: [ { key, value, severity, source, note, profile_url } ]
//           }
//         ]
//       }
//     ]
//   }

// ---------------------------------------------------------------------------
// Map points
// ---------------------------------------------------------------------------

// Extract geo-locatable points from every module's `data` block.
// The IP module attaches `data.lat` / `data.lon` plus a `data.geo` object.
// Returns points shaped for <ResultMap />: { lat, lon, target, label, isp }.
export function extractMapPoints(investigation) {
  const points = []
  const targets = investigation?.targets
  if (!Array.isArray(targets)) return points

  for (const target of targets) {
    const modules = target?.modules || []
    for (const mod of modules) {
      const data = mod?.data || {}
      const geo = data.geo || {}

      const lat = Number(data.lat ?? geo.lat)
      const lon = Number(data.lon ?? geo.lon)
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue
      if (lat === 0 && lon === 0) continue

      const label =
        [geo.city, geo.regionName || geo.region, geo.country]
          .filter(Boolean)
          .join(', ') ||
        data.reverse_dns ||
        'Unknown location'

      const isp = geo.isp || geo.org || data.cdn_or_hosting || ''

      points.push({
        lat,
        lon,
        target: target.target || mod.target || '',
        label,
        isp,
      })
    }
  }

  return points
}

// ---------------------------------------------------------------------------
// Value formatting
// ---------------------------------------------------------------------------

export function valueToString(value) {
  if (value === null || value === undefined) return ''
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (Array.isArray(value)) return value.join('; ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export function toJSON(investigation) {
  return JSON.stringify(investigation ?? {}, null, 2)
}

function csvEscape(cell) {
  const s = valueToString(cell)
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

// Flatten every finding across all targets/modules into a CSV string.
export function toCSV(investigation) {
  const headers = [
    'target',
    'target_type',
    'module',
    'key',
    'value',
    'severity',
    'source',
    'note',
    'profile_url',
  ]
  const lines = [headers.join(',')]

  const targets = investigation?.targets || []
  for (const target of targets) {
    for (const mod of target?.modules || []) {
      for (const f of mod?.findings || []) {
        lines.push(
          [
            target.target,
            target.target_type,
            mod.module,
            f.key,
            valueToString(f.value),
            f.severity || '',
            f.source || '',
            f.note || '',
            f.profile_url || '',
          ]
            .map(csvEscape)
            .join(','),
        )
      }
    }
  }

  return lines.join('\n')
}

// Filename-safe slug derived from a target string.
export function slugForFile(target) {
  const slug = (target || 'investigation')
    .toString()
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 50)
  return slug || 'investigation'
}

// Trigger a client-side file download for the given content.
export function download(filename, content, mime = 'text/plain') {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
