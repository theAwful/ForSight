/**
 * api.js ADDITIONS
 * ================
 * Add the following `tools` section to the existing `api` export object in frontend/src/api.js.
 * Also shown: the updated `jobs.output` signature (already correct in existing file if tail param works).
 *
 * INSTRUCTIONS:
 * In frontend/src/api.js, find the closing `}` of the `export const api = { ... }` object
 * and add the `tools` key before it.
 *
 * If you prefer, you can copy this entire file and replace api.js — it is a complete rewrite
 * that is backward-compatible with all existing callers.
 */

const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(BASE + path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) {
    const err = new Error(res.statusText)
    err.status = res.status
    const text = await res.text()
    try { err.body = JSON.parse(text) } catch (_) { err.body = text }
    throw err
  }
  if (res.headers.get('content-type')?.includes('application/json')) return res.json()
  return res.text()
}

export const api = {
  auth: {
    login: (username, password) =>
      request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }),
    logout: () => request('/auth/logout', { method: 'POST' }),
    me: () => request('/auth/me'),
  },
  projects: {
    list: () => request('/projects'),
    get: (id) => request(`/projects/${id}`),
    create: (name) => request('/projects', { method: 'POST', body: JSON.stringify({ name }) }),
    delete: (id) => request(`/projects/${id}`, { method: 'DELETE' }),
    nmapReady: (id) => request(`/projects/${id}/nmap-ready`),
    uploadRoe: (id, file) => {
      const form = new FormData()
      form.append('file', file)
      return request(`/projects/${id}/roe`, { method: 'POST', body: form, headers: {} })
    },
    pasteRoe: (id, content) =>
      request(`/projects/${id}/roe/paste`, { method: 'POST', body: JSON.stringify({ content }) }),
    targets: (id) => request(`/projects/${id}/targets`),
    updateTargets: (id, content) =>
      request(`/projects/${id}/targets`, { method: 'PUT', body: JSON.stringify({ content }) }),
    downloadOutputsUrl: (id) => `${BASE}/projects/${id}/download`,
    hosts: (id) => request(`/projects/${id}/hosts`),
    excludeHost: (id, host) =>
      request(`/projects/${id}/hosts/exclude`, {
        method: 'POST',
        body: JSON.stringify({ host }),
      }),
  },
  health: () => request('/health'),
  checklist: {
    list: () => request('/checklist'),
    project: (projectId) => request(`/projects/${projectId}/checklist`),
    update: (projectId, itemId, data) => {
      const q = new URLSearchParams()
      if (data.status != null) q.set('status', data.status)
      if (data.notes != null) q.set('notes', data.notes)
      return request(`/projects/${projectId}/checklist/${itemId}?${q}`, {
        method: 'PATCH',
      })
    },
  },
  jobs: {
    list: (projectId) => request(`/projects/${projectId}/jobs`),
    get: (projectId, jobId) => request(`/projects/${projectId}/jobs/${jobId}`),
    output: (projectId, jobId, tail) => {
      const q = tail != null ? `?tail=${tail}` : ''
      return request(`/projects/${projectId}/jobs/${jobId}/output${q}`)
    },
    run: (projectId, runnerKey, options = {}) =>
      request(`/projects/${projectId}/run/${runnerKey}`, {
        method: 'POST',
        body: JSON.stringify(options),
      }),
    stop: (projectId, jobId) =>
      request(`/projects/${projectId}/jobs/${jobId}/stop`, { method: 'POST' }),
    delete: (projectId, jobId) =>
      request(`/projects/${projectId}/jobs/${jobId}`, { method: 'DELETE' }),
    runPhase: (projectId, phase, options = {}) =>
      request(`/projects/${projectId}/run-phase/${phase}`, {
        method: 'POST',
        body: JSON.stringify(options),
      }),
  },
  screenshots: {
    list: (projectId) => request(`/projects/${projectId}/screenshots`),
    url: (projectId, filename) => `${BASE}/projects/${projectId}/screenshots/files/${encodeURIComponent(filename)}`,
  },
  roadmap: {
    list: () => request('/roadmap'),
  },
  feedback: {
    list: (kind) => request(kind ? `/feedback?kind=${kind}` : '/feedback'),
    create: (body) => request('/feedback', { method: 'POST', body: JSON.stringify(body) }),
  },
  nessus: {
    configured: () => request('/nessus/configured'),
    webLaunchAvailable: () => request('/nessus/web-launch-available'),
    templates: (projectId) => request(`/projects/${projectId}/nessus/templates`),
    listScans: (projectId, cacheBust = false) =>
      request(`/projects/${projectId}/nessus/scans${cacheBust ? `?_=${Date.now()}` : ''}`),
    getScan: (projectId, scanId) => request(`/projects/${projectId}/nessus/scans/${scanId}`),
    createScan: (projectId, body) =>
      request(`/projects/${projectId}/nessus/scans`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    launchScan: (projectId, scanId, options = {}) =>
      request(`/projects/${projectId}/nessus/scans/${scanId}/launch`, {
        method: 'POST',
        body: JSON.stringify(options),
      }),
    launchScanViaWeb: (projectId, scanId, body = {}) =>
      request(`/projects/${projectId}/nessus/scans/${scanId}/launch-web`, {
        method: 'POST',
        body: JSON.stringify(body || {}),
      }),
    launchScanViaWebByName: (projectId, scanName) =>
      request(`/projects/${projectId}/nessus/launch-web`, {
        method: 'POST',
        body: JSON.stringify({ scan_name: scanName }),
      }),
    deleteScanViaWeb: (projectId, scanId, body = {}) =>
      request(`/projects/${projectId}/nessus/scans/${scanId}/delete-web`, {
        method: 'POST',
        body: JSON.stringify(body || {}),
      }),
    deleteScanViaWebByName: (projectId, scanName) =>
      request(`/projects/${projectId}/nessus/delete-web`, {
        method: 'POST',
        body: JSON.stringify({ scan_name: scanName }),
      }),
    createScanViaWeb: (projectId, body) =>
      request(`/projects/${projectId}/nessus/create-scan-web`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    importScan: (projectId, scanId) =>
      request(`/projects/${projectId}/nessus/import/${scanId}`, { method: 'POST' }),
    listImports: (projectId) => request(`/projects/${projectId}/nessus/imports`),
    getImport: (projectId, scanId) => request(`/projects/${projectId}/nessus/imports/${scanId}`),
    deleteImport: (projectId, scanId) =>
      request(`/projects/${projectId}/nessus/imports/${scanId}`, { method: 'DELETE' }),
  },

  // ── Tool Management ──────────────────────────────────────────────────────
  tools: {
    /** GET /api/tools/status — returns ToolStatus[] for all configured tools */
    status: () => request('/tools/status'),

    /** GET /api/tools/status/:key — returns ToolStatus for one tool */
    statusOne: (key) => request(`/tools/status/${encodeURIComponent(key)}`),

    /** PATCH /api/tools/:key/path — update binary path (in-memory); returns updated ToolStatus */
    updatePath: (key, path) =>
      request(`/tools/${encodeURIComponent(key)}/path`, {
        method: 'PATCH',
        body: JSON.stringify({ path }),
      }),
  },
}
