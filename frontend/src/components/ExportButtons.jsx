import { useState } from 'react'
import { download, toJSON, toCSV, slugForFile } from '../lib/results.js'

export default function ExportButtons({ investigation }) {
  const [copied, setCopied] = useState(false)
  if (!investigation) return null

  const target = investigation?.targets?.[0]?.target
  const slug = slugForFile(target)

  const exportJSON = () =>
    download(`exo_${slug}.json`, toJSON(investigation), 'application/json')

  const exportCSV = () =>
    download(`exo_${slug}.csv`, toCSV(investigation), 'text/csv')

  const copyJSON = async () => {
    try {
      await navigator.clipboard.writeText(toJSON(investigation))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="flex gap-8 wrap">
      <button className="btn btn-sm" onClick={exportJSON}>
        ▾ JSON
      </button>
      <button className="btn btn-sm" onClick={exportCSV}>
        ▾ CSV
      </button>
      <button className="btn btn-sm btn-ghost" onClick={copyJSON}>
        {copied ? '✓ Copied' : '⧉ Copy raw'}
      </button>
    </div>
  )
}
