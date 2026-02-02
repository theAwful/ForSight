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
}
