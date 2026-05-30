// Thin client for the EXO-OSINT FastAPI backend.
// Base URL comes from VITE_API_URL; falls back to local dev default.

export const API_URL = (
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'
).replace(/\/+$/, '')

async function request(path, { method = 'GET', body, signal } = {}) {
  let res
  try {
    res = await fetch(`${API_URL}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal,
    })
  } catch (err) {
    if (err?.name === 'AbortError') throw err
    throw new Error(
      `network error contacting ${API_URL} — is the backend running? (${err.message})`,
    )
  }

  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }

  if (!res.ok) {
    const detail =
      (data && (data.detail || data.message)) || `HTTP ${res.status}`
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  return data
}

export const api = {
  health: (opts) => request('/api/health', opts),
  version: (opts) => request('/api/version', opts),
  modules: (opts) => request('/api/modules', opts),

  detect: (target, opts = {}) =>
    request('/api/detect', { method: 'POST', body: { target }, ...opts }),

  investigate: (payload, opts = {}) =>
    request('/api/investigate', { method: 'POST', body: payload, ...opts }),
}
