import { useState, useEffect } from 'react'
import { api } from './api'

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, none: 0, info: 0 }
const SEVERITY_COLOR = { critical: '#8b0000', high: '#c00', medium: '#e09000', low: '#366', none: '#666', info: '#4a6fa5' }

function severityRank(s) {
  if (s == null) return 0
  const v = String(s).toLowerCase()
  return SEVERITY_ORDER[v] ?? (parseInt(v, 10) >= 4 ? 4 : parseInt(v, 10) >= 3 ? 3 : parseInt(v, 10) >= 2 ? 2 : 1)
}

function severityLabel(s) {
  if (s == null) return 'Info'
  const n = parseInt(s, 10)
  if (!Number.isNaN(n)) {
    const labels = ['None', 'Low', 'Medium', 'High', 'Critical']
    return labels[Math.min(Math.max(n, 0), 4)] || String(s)
  }
  const v = String(s).toLowerCase()
  return v.charAt(0).toUpperCase() + v.slice(1)
}

function severityColor(s) {
  const v = String(s).toLowerCase()
  if (SEVERITY_COLOR[v]) return SEVERITY_COLOR[v]
  const n = parseInt(s, 10)
  if (!Number.isNaN(n)) {
    const colors = ['#666', '#366', '#e09000', '#c00', '#8b0000']
    return colors[Math.min(Math.max(n, 0), 4)] || SEVERITY_COLOR.none
  }
  return SEVERITY_COLOR.none
}

function formatLastRun(value) {
  if (value == null || value === '' || value === 0) return 'Never'
  const n = Number(value)
  if (Number.isNaN(n) || n <= 0) return 'Never'
  const ms = n > 1e12 ? n : n * 1000
  const date = new Date(ms)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
}

function formatStatus(status) {
  if (status == null || status === '') return 'N/A'
  const s = String(status).toLowerCase()
  const map = { paused: 'Paused', running: 'Running', completed: 'Completed', canceled: 'Canceled', empty: 'Empty', cancelled: 'Canceled' }
  return map[s] || (s.charAt(0).toUpperCase() + s.slice(1))
}

function statusBadgeStyle(status) {
  const s = String(status || '').toLowerCase()
  const colors = {
    paused: { background: 'var(--warn, #e09000)', color: '#fff', padding: '0.2rem 0.45rem', borderRadius: 4, fontSize: '0.8rem' },
    running: { background: 'var(--primary)', color: 'var(--primary-text, #fff)', padding: '0.2rem 0.45rem', borderRadius: 4, fontSize: '0.8rem' },
    completed: { background: 'var(--accent)', color: '#fff', padding: '0.2rem 0.45rem', borderRadius: 4, fontSize: '0.8rem' },
    canceled: { background: 'var(--text-muted)', color: '#fff', padding: '0.2rem 0.45rem', borderRadius: 4, fontSize: '0.8rem' },
    cancelled: { background: 'var(--text-muted)', color: '#fff', padding: '0.2rem 0.45rem', borderRadius: 4, fontSize: '0.8rem' },
    empty: { background: 'var(--border)', color: 'var(--text-muted)', padding: '0.2rem 0.45rem', borderRadius: 4, fontSize: '0.8rem' },
  }
  return colors[s] || { padding: '0.2rem 0.45rem', borderRadius: 4, fontSize: '0.8rem', background: 'var(--border)', color: 'var(--text)' }
}

export default function Nessus({ projectId, onRefresh }) {
  const [configured, setConfigured] = useState(false)
  const [scans, setScans] = useState([])
  const [imports, setImports] = useState([])
  const [importDetail, setImportDetail] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [importing, setImporting] = useState(null)
  const [launching, setLaunching] = useState(null)
  const [deleting, setDeleting] = useState(null)
  const [view, setView] = useState('imported')
  const [selectedImportId, setSelectedImportId] = useState(null)
  const [detailType, setDetailType] = useState(null)
  const [detailVuln, setDetailVuln] = useState(null)
  const [detailHost, setDetailHost] = useState(null)
  const [vulnSearch, setVulnSearch] = useState('')
  const [scanSubView, setScanSubView] = useState('vulns')
  const [templates, setTemplates] = useState([])
  const [createName, setCreateName] = useState('')
  const [createTemplateUuid, setCreateTemplateUuid] = useState('')
  const [createExtraTargets, setCreateExtraTargets] = useState('')
  const [creating, setCreating] = useState(false)
  const [creatingViaWeb, setCreatingViaWeb] = useState(false)
  const [createError, setCreateError] = useState(null)
  const [showCreate, setShowCreate] = useState(false)
  const [webLaunchInfo, setWebLaunchInfo] = useState(null)

  useEffect(() => {
    if (!projectId) return
    setError(null)
    api.nessus
      .configured()
      .then((r) => setConfigured(r?.configured === true))
      .catch(() => setConfigured(false))
  }, [projectId])

  useEffect(() => {
    if (!configured) return
    api.nessus
      .webLaunchAvailable()
      .then(setWebLaunchInfo)
      .catch(() => setWebLaunchInfo(null))
  }, [configured])

  useEffect(() => {
    if (!projectId || !configured) {
      setScans([])
      setLoading(false)
      return
    }
    setLoading(true)
    setError(null)
    Promise.all([
      api.nessus.listScans(projectId).then((data) => {
        const list = data?.scans ?? []
        return Array.isArray(list) ? list : []
      }),
      api.nessus.listImports(projectId).then((data) => {
        const list = data?.scans ?? []
        return Array.isArray(list) ? list : []
      }),
    ])
      .then(([scanList, importList]) => {
        setScans(scanList)
        setImports(importList)
      })
      .catch((err) => {
        setScans([])
        setImports([])
        setError(err?.body?.detail ?? err?.message ?? 'Failed to load')
      })
      .finally(() => setLoading(false))
  }, [projectId, configured])

  useEffect(() => {
    if (!projectId || !configured) return
    api.nessus
      .templates(projectId)
      .then((data) => {
        const list = data?.items ?? data?.templates ?? data ?? []
        setTemplates(Array.isArray(list) ? list : [])
      })
      .catch(() => setTemplates([]))
  }, [projectId, configured])

  const loadImports = () => {
    return api.nessus.listImports(projectId).then((data) => {
      const list = data?.scans ?? []
      setImports(Array.isArray(list) ? list : [])
    })
  }

  const loadScans = (fresh = false) => {
    return api.nessus.listScans(projectId, fresh).then((data) => {
      const list = data?.scans ?? []
      setScans(Array.isArray(list) ? list : [])
    })
  }

  const doImport = async (scanId) => {
    setImporting(scanId)
    setError(null)
    try {
      await api.nessus.importScan(projectId, scanId)
      await loadImports()
      onRefresh?.()
    } catch (err) {
      setError(err?.body?.detail ?? err?.message ?? 'Import failed')
    } finally {
      setImporting(null)
    }
  }

  const launchScan = async (scanId, useProjectTargets = true) => {
    setLaunching(scanId)
    setError(null)
    try {
      await api.nessus.launchScan(projectId, scanId, { use_project_targets: useProjectTargets })
      onRefresh?.()
      await loadScans()
    } catch (err) {
      setError(err?.body?.detail ?? err?.message ?? 'Launch failed')
    } finally {
      setLaunching(null)
    }
  }

  // Find the row by scan name in Nessus and click the launch button to the right of that name (we don't use scan/button id).
  const launchScanViaWeb = async (scanId, scanName) => {
    const rowKey = scanId ?? scanName
    const displayName = (scanName ?? (scanId != null ? `Scan ${scanId}` : '')).trim()
    if (!displayName) {
      setError('Scan name is required to launch via web')
      return
    }
    setLaunching(rowKey)
    setError(null)
    try {
      await api.nessus.launchScanViaWebByName(projectId, displayName)
      onRefresh?.()
      await loadScans(true)
    } catch (err) {
      setError(err?.body?.detail ?? err?.message ?? 'Web launch failed')
    } finally {
      setLaunching(null)
    }
  }

  const deleteScanViaWeb = async (scanId, scanName) => {
    const displayName = (scanName ?? (scanId != null ? `Scan ${scanId}` : '')).trim()
    if (!window.confirm(`Delete scan "${displayName || scanId}" from Nessus? This cannot be undone.`)) return
    const rowKey = scanId ?? scanName
    setDeleting(rowKey)
    setError(null)
    try {
      await api.nessus.deleteScanViaWebByName(projectId, displayName || String(scanId))
      onRefresh?.()
      await loadScans(true)
    } catch (err) {
      setError(err?.body?.detail ?? err?.message ?? 'Delete failed')
    } finally {
      setDeleting(null)
    }
  }

  useEffect(() => {
    if (!projectId || selectedImportId == null) {
      setImportDetail(null)
      return
    }
    setDetailType(null)
    setDetailVuln(null)
    setDetailHost(null)
    api.nessus
      .getImport(projectId, selectedImportId)
      .then(setImportDetail)
      .catch(() => setImportDetail(null))
  }, [projectId, selectedImportId])

  const createScan = async () => {
    const name = (createName || '').trim()
    if (!name) {
      setCreateError('Enter a scan name')
      return
    }
    if (!createTemplateUuid) {
      setCreateError('Select a template')
      return
    }
    setCreating(true)
    setCreateError(null)
    try {
      await api.nessus.createScan(projectId, {
        name,
        template_uuid: createTemplateUuid,
        use_project_targets: true,
        text_targets: createExtraTargets.trim() || undefined,
      })
      setCreateName('')
      setCreateTemplateUuid('')
      setCreateExtraTargets('')
      await loadScans()
      onRefresh?.()
    } catch (err) {
      setCreateError(err?.body?.detail ?? err?.message ?? 'Create failed')
    } finally {
      setCreating(false)
    }
  }

  const createScanViaWeb = async () => {
    const name = (createName || '').trim()
    if (!name) {
      setCreateError('Enter a scan name')
      return
    }
    const selectedTemplate = createTemplateUuid
      ? templates.find(
          (t) =>
            (t.uuid || (t.type === 'policy' && t.id != null ? `policy:${t.id}` : '') || t.id) === createTemplateUuid
        )
      : null
    const templateKey = selectedTemplate?.name || selectedTemplate?.title || 'advanced'
    setCreatingViaWeb(true)
    setCreateError(null)
    try {
      await api.nessus.createScanViaWeb(projectId, {
        name,
        template_key: templateKey,
        use_project_targets: true,
        text_targets: createExtraTargets.trim() || undefined,
      })
      setCreateName('')
      setCreateTemplateUuid('')
      setCreateExtraTargets('')
      await loadScans(true)
      onRefresh?.()
    } catch (err) {
      setCreateError(err?.body?.detail ?? err?.message ?? 'Create via web failed')
    } finally {
      setCreatingViaWeb(false)
    }
  }

  const deleteImport = async (scanId) => {
    try {
      await api.nessus.deleteImport(projectId, scanId)
      if (selectedImportId === scanId) {
        setSelectedImportId(null)
        setImportDetail(null)
      }
      await loadImports()
      onRefresh?.()
    } catch (err) {
      setError(err?.body?.detail ?? err?.message ?? 'Delete failed')
    }
  }

  const hosts = importDetail?.hosts ?? []
  const vulnsFlat = []
  const vulnKeyToInstances = {}
  hosts.forEach((h) => {
    (h.vulns || []).forEach((v) => {
      const key = `${v.plugin_id}-${v.port || 0}-${v.protocol || ''}`
      vulnsFlat.push({ ...v, _host: h })
      if (!vulnKeyToInstances[key]) vulnKeyToInstances[key] = []
      vulnKeyToInstances[key].push({ ...v, host: h })
    })
  })
  const vulnsByPlugin = {}
  vulnsFlat.forEach((v) => {
    const id = v.plugin_id || 'unknown'
    if (!vulnsByPlugin[id]) vulnsByPlugin[id] = { vuln: v, count: 0, hosts: new Set() }
    vulnsByPlugin[id].count += 1
    vulnsByPlugin[id].hosts.add(v._host?.host_ip || v._host?.name || '')
  })
  const vulnList = Object.entries(vulnsByPlugin)
    .map(([id, o]) => ({ plugin_id: id, ...o.vuln, affected_count: o.count, affected_hosts: [...o.hosts] }))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))

  const vulnSearchLower = (vulnSearch || '').trim().toLowerCase()
  const filteredVulnList = vulnSearchLower
    ? vulnList.filter(
        (v) =>
          (v.plugin_name || '').toLowerCase().includes(vulnSearchLower) ||
          (v.plugin_id || '').toString().includes(vulnSearchLower)
      )
    : vulnList

  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
  vulnList.forEach((v) => {
    const label = severityLabel(v.severity)
    if (severityCounts[label] !== undefined) severityCounts[label] += 1
    else severityCounts.Info += 1
  })

  if (!configured) {
    return (
      <div style={styles.card}>
        <h2 style={styles.title}>Nessus</h2>
        <p style={styles.muted}>
          Configure the backend (e.g. <code>backend/.env</code>). For Nessus Pro you can use either: (1) API keys —
          <code>FORSIGHT_TENABLE_ACCESS_KEY</code> and <code>FORSIGHT_TENABLE_SECRET_KEY</code> from Nessus → My Account → API Keys;
          or (2) session login — <code>FORSIGHT_TENABLE_USERNAME</code> and <code>FORSIGHT_TENABLE_PASSWORD</code> (enables launch scans).
          Default URL is <code>https://127.0.0.1:8834</code>. Set <code>FORSIGHT_TENABLE_VERIFY_SSL=false</code> for self-signed certs.
        </p>
      </div>
    )
  }

  if (loading && !imports.length) {
    return (
      <div style={styles.card}>
        <h2 style={styles.title}>Nessus</h2>
        <p style={styles.muted}>Loading…</p>
      </div>
    )
  }

  return (
    <div style={styles.wrapper}>
      <div style={styles.header}>
        <h2 style={styles.title}>Nessus</h2>
        <div style={styles.headerActions}>
          <button
            type="button"
            className={view === 'imported' ? 'btn-primary' : 'btn-secondary'}
            onClick={() => setView('imported')}
            style={styles.tabBtn}
          >
            Imported results
          </button>
          <button
            type="button"
            className={view === 'scans' ? 'btn-primary' : 'btn-secondary'}
            onClick={() => setView('scans')}
            style={styles.tabBtn}
          >
            Available scans
          </button>
          <button type="button" className="btn-secondary" onClick={() => loadImports().then(() => loadScans(true))}>
            Refresh
          </button>
        </div>
      </div>
      {error && <div style={styles.error}>{error}</div>}

      {view === 'imported' && (
        <div style={styles.importedSection}>
          {!imports.length ? (
            <div style={styles.importedList}>
              <h3 style={styles.subtitle}>Imported scan results</h3>
              <p style={styles.muted}>No imported results yet. Switch to &quot;Available scans&quot; and use &quot;Import results&quot; on a scan.</p>
            </div>
          ) : (
            <>
              {selectedImportId == null ? (
                <div style={styles.importedList}>
                  <h3 style={styles.subtitle}>Imported scan results</h3>
                  <p style={styles.muted}>Select a scan to view vulnerabilities and hosts.</p>
                  <ul style={styles.importList}>
                    {imports.map((imp) => (
                      <li
                        key={imp.scan_id}
                        style={{
                          ...styles.importItem,
                          ...(selectedImportId === imp.scan_id ? styles.importItemActive : {}),
                        }}
                        onClick={() => {
                          setSelectedImportId(imp.scan_id)
                          setDetailVuln(null)
                          setDetailHost(null)
                          setScanSubView('vulns')
                        }}
                      >
                        <div style={styles.importName}>{imp.scan_name || `Scan ${imp.scan_id}`}</div>
                        <div style={styles.importMeta}>
                          {imp.hosts_count ?? 0} hosts · {imp.vulns_count ?? 0} findings · {imp.imported_at ? new Date(imp.imported_at).toLocaleString() : ''}
                        </div>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={styles.deleteImportBtn}
                          onClick={(e) => {
                            e.stopPropagation()
                            if (window.confirm('Remove this imported scan from the project?')) deleteImport(imp.scan_id)
                          }}
                        >
                          Remove
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : !importDetail ? (
                <div style={styles.importedList}>
                  <p style={styles.muted}>Loading scan…</p>
                </div>
              ) : (detailVuln || detailHost ? (
                <div style={styles.findingsDetailRoot}>
                  {detailVuln && (
                    <>
                      <div style={styles.findingsDetailHeader}>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={styles.backBtn}
                          onClick={() => { setDetailVuln(null); setDetailHost(null) }}
                        >
                          ← Back to Vulnerabilities
                        </button>
                        <span style={styles.findingsDetailBreadcrumb}>
                          {importDetail.scan_name || `Scan ${selectedImportId}`} / Plugin #{detailVuln.plugin_id}
                        </span>
                      </div>
                      <div style={styles.findingsDetailLayout}>
                        <div style={styles.findingsDetailMain}>
                          <div style={styles.findingsDetailTitleRow}>
                            <span
                              style={{
                                ...styles.severityBadge,
                                background: severityColor(detailVuln.severity),
                                color: '#fff',
                              }}
                            >
                              {severityLabel(detailVuln.severity).toUpperCase()}
                            </span>
                            <h3 style={styles.findingsDetailTitle}>{detailVuln.plugin_name || `Plugin ${detailVuln.plugin_id}`}</h3>
                          </div>
                          {detailVuln.synopsis && (
                            <p style={styles.findingsSynopsis}>{detailVuln.synopsis}</p>
                          )}
                          {detailVuln.description && (
                            <section style={styles.findingsSection}>
                              <h4 style={styles.findingsSectionTitle}>Description</h4>
                              <div style={styles.findingsSectionBody}>
                                <pre style={styles.pre}>{detailVuln.description}</pre>
                              </div>
                            </section>
                          )}
                          {detailVuln.solution && (
                            <section style={styles.findingsSection}>
                              <h4 style={styles.findingsSectionTitle}>Solution</h4>
                              <div style={styles.findingsSectionBody}>
                                <pre style={styles.pre}>{detailVuln.solution}</pre>
                              </div>
                            </section>
                          )}
                          {detailVuln.plugin_output && (
                            <section style={styles.findingsSection}>
                              <h4 style={styles.findingsSectionTitle}>Output</h4>
                              <div style={styles.findingsSectionBody}>
                                <pre style={styles.pre}>{detailVuln.plugin_output}</pre>
                              </div>
                            </section>
                          )}
                          <section style={styles.findingsSection}>
                            <h4 style={styles.findingsSectionTitle}>Affected hosts ({detailVuln.affected_count ?? 0})</h4>
                            <div style={styles.findingsSectionBody}>
                              {(detailVuln.affected_hosts || []).join(', ') || '—'}
                            </div>
                          </section>
                        </div>
                        <aside style={styles.findingsSidebar}>
                          <div style={styles.findingsSidebarBlock}>
                            <h4 style={styles.findingsSidebarTitle}>Plugin details</h4>
                            <dl style={styles.findingsSidebarDl}>
                              <dt style={styles.findingsSidebarDt}>Severity</dt>
                              <dd style={styles.findingsSidebarDd}>{severityLabel(detailVuln.severity)}</dd>
                              <dt style={styles.findingsSidebarDt}>ID</dt>
                              <dd style={styles.findingsSidebarDd}>{detailVuln.plugin_id}</dd>
                              <dt style={styles.findingsSidebarDt}>Port</dt>
                              <dd style={styles.findingsSidebarDd}>{detailVuln.port || '—'}</dd>
                              <dt style={styles.findingsSidebarDt}>Protocol</dt>
                              <dd style={styles.findingsSidebarDd}>{detailVuln.protocol || '—'}</dd>
                              {detailVuln.risk_factor && (
                                <>
                                  <dt style={styles.findingsSidebarDt}>Risk factor</dt>
                                  <dd style={styles.findingsSidebarDd}>{detailVuln.risk_factor}</dd>
                                </>
                              )}
                            </dl>
                          </div>
                        </aside>
                      </div>
                    </>
                  )}
                  {detailHost && (
                    <>
                      <div style={styles.findingsDetailHeader}>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={styles.backBtn}
                          onClick={() => { setDetailVuln(null); setDetailHost(null) }}
                        >
                          ← Back to Hosts
                        </button>
                        <span style={styles.findingsDetailBreadcrumb}>
                          {importDetail.scan_name || `Scan ${selectedImportId}`} / {detailHost.name || detailHost.host_ip}
                        </span>
                      </div>
                      <div style={styles.findingsDetailLayout}>
                        <div style={styles.findingsDetailMain}>
                          <h3 style={styles.findingsDetailTitle}>{detailHost.name || detailHost.host_ip}</h3>
                          <p style={styles.detailMeta}>IP: {detailHost.host_ip} · {(detailHost.vulns || []).length} findings</p>
                          {(detailHost.vulns || []).map((v, i) => (
                            <div key={i} style={styles.hostVulnCard}>
                              <div style={styles.findingsDetailTitleRow}>
                                <span
                                  style={{
                                    ...styles.severityBadge,
                                    background: severityColor(v.severity),
                                    color: '#fff',
                                  }}
                                >
                                  {severityLabel(v.severity).toUpperCase()}
                                </span>
                                <h4 style={styles.findingsDetailTitle}>{v.plugin_name || `Plugin ${v.plugin_id}`}</h4>
                              </div>
                              {v.synopsis && <p style={styles.findingsSynopsis}>{v.synopsis}</p>}
                              {v.description && (
                                <section style={styles.findingsSection}>
                                  <h4 style={styles.findingsSectionTitle}>Description</h4>
                                  <div style={styles.findingsSectionBody}>
                                    <pre style={styles.pre}>{v.description}</pre>
                                  </div>
                                </section>
                              )}
                              {v.solution && (
                                <section style={styles.findingsSection}>
                                  <h4 style={styles.findingsSectionTitle}>Solution</h4>
                                  <div style={styles.findingsSectionBody}>
                                    <pre style={styles.pre}>{v.solution}</pre>
                                  </div>
                                </section>
                              )}
                              {v.plugin_output && (
                                <section style={styles.findingsSection}>
                                  <h4 style={styles.findingsSectionTitle}>Output</h4>
                                  <div style={styles.findingsSectionBody}>
                                    <pre style={styles.pre}>{v.plugin_output}</pre>
                                  </div>
                                </section>
                              )}
                            </div>
                          ))}
                        </div>
                        <aside style={styles.findingsSidebar}>
                          <div style={styles.findingsSidebarBlock}>
                            <h4 style={styles.findingsSidebarTitle}>Host details</h4>
                            <dl style={styles.findingsSidebarDl}>
                              <dt style={styles.findingsSidebarDt}>Host / Name</dt>
                              <dd style={styles.findingsSidebarDd}>{detailHost.name || '—'}</dd>
                              <dt style={styles.findingsSidebarDt}>IP</dt>
                              <dd style={styles.findingsSidebarDd}>{detailHost.host_ip || '—'}</dd>
                              <dt style={styles.findingsSidebarDt}>Findings</dt>
                              <dd style={styles.findingsSidebarDd}>{(detailHost.vulns || []).length}</dd>
                            </dl>
                          </div>
                          <div style={styles.findingsSidebarBlock}>
                            <h4 style={styles.findingsSidebarTitle}>Plugins on this host</h4>
                            <div style={styles.findingsSectionBody}>
                              {(detailHost.vulns || []).map((v, i) => (
                                <div key={i} style={styles.hostPluginRow}>
                                  <span
                                    style={{
                                      ...styles.severityBadge,
                                      background: severityColor(v.severity),
                                      color: '#fff',
                                      fontSize: '0.7rem',
                                      padding: '0.1rem 0.35rem',
                                    }}
                                  >
                                    {severityLabel(v.severity)}
                                  </span>
                                  <span style={styles.hostPluginId}>#{v.plugin_id}</span>
                                  <span style={styles.vulnMeta}>{v.port || '—'}/{v.protocol || '—'}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </aside>
                      </div>
                    </>
                  )}
                </div>
              ) : (
                <div style={styles.findingsRoot}>
                  <div style={styles.findingsScanHeader}>
                    <button
                      type="button"
                      className="btn-secondary"
                      style={styles.backBtn}
                      onClick={() => setSelectedImportId(null)}
                    >
                      ← Back to scan list
                    </button>
                    <h3 style={styles.findingsScanTitle}>{importDetail.scan_name || `Scan ${selectedImportId}`}</h3>
                  </div>
                  <div style={styles.findingsTabs}>
                    <button
                      type="button"
                      style={{
                        ...styles.findingsTab,
                        ...(scanSubView === 'vulns' ? styles.findingsTabActive : {}),
                      }}
                      onClick={() => setScanSubView('vulns')}
                    >
                      Vulnerabilities {vulnList.length}
                    </button>
                    <button
                      type="button"
                      style={{
                        ...styles.findingsTab,
                        ...(scanSubView === 'hosts' ? styles.findingsTabActive : {}),
                      }}
                      onClick={() => setScanSubView('hosts')}
                    >
                      Hosts {hosts.length}
                    </button>
                  </div>

                  {scanSubView === 'vulns' && (
                    <div style={styles.findingsContent}>
                      <div style={styles.findingsToolbar}>
                        <input
                          type="text"
                          placeholder="Search vulnerabilities…"
                          value={vulnSearch}
                          onChange={(e) => setVulnSearch(e.target.value)}
                          style={styles.findingsSearch}
                        />
                        <span style={styles.findingsCount}>{filteredVulnList.length} vulnerabilities</span>
                      </div>
                      <div style={styles.findingsVulnLayout}>
                        <div style={styles.findingsTableWrap}>
                          <table className="findings-table" style={styles.findingsTable}>
                            <thead>
                              <tr>
                                <th style={styles.findingsTh}>Sev</th>
                                <th style={styles.findingsTh}>Name</th>
                                <th style={styles.findingsTh}>Count</th>
                              </tr>
                            </thead>
                            <tbody>
                              {filteredVulnList.length === 0 ? (
                                <tr>
                                  <td colSpan={3} style={styles.findingsTd}>
                                    {vulnList.length === 0 ? 'No vulnerabilities in this scan.' : 'No matches for search.'}
                                  </td>
                                </tr>
                              ) : (
                                filteredVulnList.map((v) => (
                                  <tr
                                    key={`${v.plugin_id}-${v.port}-${v.protocol}`}
                                    style={styles.findingsTr}
                                    onClick={() => {
                                      setDetailVuln(v)
                                      setDetailHost(null)
                                    }}
                                  >
                                    <td style={styles.findingsTd}>
                                      <span
                                        style={{
                                          ...styles.severityBadge,
                                          background: severityColor(v.severity),
                                          color: '#fff',
                                        }}
                                      >
                                        {severityLabel(v.severity).toUpperCase()}
                                      </span>
                                    </td>
                                    <td style={styles.findingsTdName}>{v.plugin_name || v.plugin_id}</td>
                                    <td style={styles.findingsTd}>{v.affected_count}</td>
                                  </tr>
                                ))
                              )}
                            </tbody>
                          </table>
                        </div>
                        <div style={styles.findingsSummary}>
                          <h4 style={styles.findingsSummaryTitle}>By severity</h4>
                          <div style={styles.findingsSummaryList}>
                            {['Critical', 'High', 'Medium', 'Low', 'Info'].map((label) => (
                              <div key={label} style={styles.findingsSummaryRow}>
                                <span style={{ ...styles.severityDot, background: severityColor(label.toLowerCase()) }} />
                                <span>{label}</span>
                                <span style={styles.findingsSummaryCount}>{severityCounts[label] ?? 0}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {scanSubView === 'hosts' && (
                    <div style={styles.findingsContent}>
                      <div style={styles.findingsTableWrap}>
                        <table className="findings-table" style={styles.findingsTable}>
                          <thead>
                            <tr>
                              <th style={styles.findingsTh}>Host</th>
                              <th style={styles.findingsTh}>Findings</th>
                            </tr>
                          </thead>
                          <tbody>
                            {hosts.length === 0 ? (
                              <tr>
                                <td colSpan={2} style={styles.findingsTd}>No hosts.</td>
                              </tr>
                            ) : (
                              hosts.map((h) => (
                                <tr
                                  key={h.host_ip || h.name}
                                  style={styles.findingsTr}
                                  onClick={() => {
                                    setDetailHost(h)
                                    setDetailVuln(null)
                                  }}
                                >
                                  <td style={styles.findingsTdName}>{h.name || h.host_ip}</td>
                                  <td style={styles.findingsTd}>{(h.vulns || []).length}</td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {view === 'scans' && (
        <div style={styles.scansSection}>
          <h3 style={styles.subtitle}>Scans from Nessus</h3>
          <p style={styles.muted}>Import results from a scan to view vulnerabilities and hosts in ForSight. Use &quot;Import results&quot; to pull findings into this project.</p>
          {!scans.length ? (
            <p style={styles.muted}>No scans found. Create one below or in Nessus; they will appear here after refresh.</p>
          ) : (
            <div style={styles.tableWrap}>
              <table style={styles.table}>
                <thead>
                  <tr>
                    <th style={styles.th}>Name</th>
                    <th style={styles.th}>Status</th>
                    <th style={styles.th}>Last run</th>
                    <th style={styles.th}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s, idx) => {
                    const rowKey = s.id ?? s.name ?? idx
                    const displayName = s.name ?? `Scan ${s.id}`
                    return (
                      <tr key={rowKey}>
                        <td style={styles.td}>{displayName}</td>
                        <td style={styles.td}>
                          <span style={statusBadgeStyle(s.status)} title={s.status || ''}>
                            {formatStatus(s.status)}
                          </span>
                        </td>
                        <td style={styles.td}>{formatLastRun(s.last_modification_date)}</td>
                        <td style={styles.td}>
                          {webLaunchInfo?.available ? (
                            <button
                              type="button"
                              className="btn-primary"
                              disabled={launching === rowKey}
                              onClick={() => launchScanViaWeb(s.id, s.name)}
                              title="Launch via Nessus web UI (by scan name in this row)"
                              style={styles.actionBtn}
                            >
                              {launching === rowKey ? 'Launching…' : 'Launch (via web)'}
                            </button>
                          ) : (
                            <button
                              type="button"
                              className="btn-primary"
                              disabled={launching === rowKey}
                              onClick={() => launchScan(s.id, true)}
                              title="Launch via API (if supported)"
                              style={styles.actionBtn}
                            >
                              {launching === rowKey ? 'Launching…' : 'Launch'}
                            </button>
                          )}
                          {webLaunchInfo?.open_url && (
                            <button
                              type="button"
                              className="btn-secondary"
                              style={styles.actionBtn}
                              onClick={() => window.open(webLaunchInfo.open_url, '_blank', 'noopener,noreferrer')}
                            >
                              Open in Nessus
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn-secondary"
                            disabled={importing === s.id}
                            onClick={() => doImport(s.id)}
                            title="Import scan results into this project"
                            style={styles.actionBtn}
                          >
                            {importing === s.id ? 'Importing…' : 'Import results'}
                          </button>
                          {webLaunchInfo?.available && (
                            <button
                              type="button"
                              className="btn-secondary"
                              disabled={deleting === rowKey}
                              onClick={() => deleteScanViaWeb(s.id, s.name)}
                              title="Delete scan from Nessus (Trash)"
                              style={{ ...styles.actionBtn, color: 'var(--danger, #c00)' }}
                            >
                              {deleting === rowKey ? 'Deleting…' : 'Trash'}
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          <div style={styles.createSection}>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => setShowCreate(!showCreate)}
              style={styles.collapseBtn}
            >
              {showCreate ? 'Hide create scan' : 'Create new scan (optional)'}
            </button>
            {showCreate && (
              <div style={styles.createCard}>
                <div style={styles.createRow}>
                  <label style={styles.label}>Scan name</label>
                  <input
                    type="text"
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                    placeholder="e.g. ForSight scan"
                    style={styles.input}
                  />
                </div>
                <div style={styles.createRow}>
                  <label style={styles.label}>Template</label>
                  <select value={createTemplateUuid} onChange={(e) => setCreateTemplateUuid(e.target.value)} style={styles.select}>
                    <option value="">— Select template or policy —</option>
                    {templates.map((t) => {
                      const value = t.uuid || (t.type === 'policy' && t.id != null ? `policy:${t.id}` : '') || t.id || ''
                      const label = t.name || t.title || (t.type === 'policy' ? `Policy ${t.id}` : t.uuid) || `Item ${t.id}`
                      return (
                        <option key={value || label} value={value}>
                          {t.type === 'policy' ? `[Policy] ${label}` : label}
                        </option>
                      )
                    })}
                  </select>
                </div>
                <div style={styles.createRow}>
                  <label style={styles.label}>Extra targets (optional)</label>
                  <textarea
                    value={createExtraTargets}
                    onChange={(e) => setCreateExtraTargets(e.target.value)}
                    placeholder="Additional IPs or hostnames"
                    style={styles.textarea}
                    rows={2}
                  />
                </div>
                {createError && <div style={styles.error}>{createError}</div>}
                <div style={styles.createBtnRow}>
                  <button type="button" className="btn-primary" disabled={creating || creatingViaWeb} onClick={createScan} style={styles.createBtn}>
                    {creating ? 'Creating…' : 'Create scan (API)'}
                  </button>
                  {webLaunchInfo?.available && (
                    <button type="button" className="btn-primary" disabled={creating || creatingViaWeb} onClick={createScanViaWeb} style={styles.createBtn}>
                      {creatingViaWeb ? 'Creating…' : 'Create via web'}
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

const styles = {
  wrapper: { padding: '0.5rem 0' },
  card: { padding: '1rem' },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' },
  headerActions: { display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' },
  title: { margin: 0, fontSize: '1.25rem' },
  subtitle: { margin: '0 0 0.5rem 0', fontSize: '1rem' },
  tabBtn: { marginRight: '0.25rem' },
  muted: { color: 'var(--text-muted)', margin: 0 },
  error: { color: 'var(--danger, #c00)', marginBottom: '1rem' },
  importedSection: { display: 'flex', flexDirection: 'column', gap: '1rem' },
  importedList: { flex: '0 0 auto' },
  importList: { listStyle: 'none', padding: 0, margin: 0 },
  importItem: {
    padding: '0.75rem',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    marginBottom: '0.5rem',
    cursor: 'pointer',
    display: 'flex',
    flexWrap: 'wrap',
    alignItems: 'center',
    gap: '0.5rem',
  },
  importItemActive: { borderColor: 'var(--primary)', background: 'var(--bg-subtle, #f5f5f5)' },
  importName: { fontWeight: 600 },
  importMeta: { fontSize: '0.9rem', color: 'var(--text-muted)' },
  deleteImportBtn: { marginLeft: 'auto' },
  detailArea: { border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1rem' },
  twoCol: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' },
  panel: { minWidth: 0 },
  panelTitle: { margin: '0 0 0.5rem 0', fontSize: '0.95rem' },
  vulnList: { maxHeight: 320, overflowY: 'auto' },
  vulnRow: {
    padding: '0.4rem 0.5rem',
    borderLeft: '3px solid #666',
    marginBottom: 2,
    cursor: 'pointer',
    borderRadius: 2,
    background: 'var(--bg-subtle, #fafafa)',
  },
  vulnName: { display: 'block', fontWeight: 500 },
  vulnMeta: { fontSize: '0.85rem', color: 'var(--text-muted)' },
  hostList: { maxHeight: 320, overflowY: 'auto' },
  hostRow: {
    padding: '0.4rem 0.5rem',
    marginBottom: 2,
    cursor: 'pointer',
    borderRadius: 2,
    background: 'var(--bg-subtle, #fafafa)',
    border: '1px solid transparent',
  },
  hostName: { fontWeight: 500 },
  detailPanel: { marginTop: '1rem', padding: '1rem', border: '1px solid var(--border)', borderRadius: 'var(--radius)', minHeight: 120 },
  detailContent: {},
  detailTitle: { margin: '0 0 0.5rem 0' },
  detailMeta: { fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '0.5rem' },
  detailBlock: { marginTop: '0.75rem' },
  pre: { whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '0.9rem', margin: '0.25rem 0', padding: '0.5rem', background: 'var(--bg-subtle)', borderRadius: 4, maxHeight: 300, overflow: 'auto' },
  preSmall: { whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '0.85rem', margin: '0.25rem 0', padding: '0.25rem', background: 'var(--bg-subtle)', borderRadius: 4 },
  hostVuln: { marginBottom: '0.75rem' },
  scansSection: {},
  tableWrap: { overflowX: 'auto' },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { textAlign: 'left', padding: '0.5rem 0.75rem', borderBottom: '1px solid var(--border)' },
  td: { padding: '0.5rem 0.75rem', borderBottom: '1px solid var(--border)' },
  actionBtn: { marginRight: '0.5rem' },
  createSection: { marginTop: '1.5rem' },
  collapseBtn: { marginBottom: '0.5rem' },
  createCard: { marginBottom: '1rem', padding: '1rem', border: '1px solid var(--border)', borderRadius: 'var(--radius)' },
  createRow: { marginBottom: '0.75rem' },
  label: { display: 'block', marginBottom: '0.25rem', fontSize: '0.9rem' },
  input: { width: '100%', maxWidth: 400, padding: '0.4rem 0.5rem', borderRadius: 'var(--radius)', border: '1px solid var(--border)' },
  select: { width: '100%', maxWidth: 400, padding: '0.4rem 0.5rem', borderRadius: 'var(--radius)', border: '1px solid var(--border)' },
  textarea: { width: '100%', maxWidth: 400, padding: '0.4rem 0.5rem', borderRadius: 'var(--radius)', border: '1px solid var(--border)', resize: 'vertical' },
  createBtn: { marginTop: '0.5rem', marginRight: '0.5rem' },
  createBtnRow: { display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' },
  backBtn: { marginBottom: '0.5rem' },
  findingsRoot: { border: '1px solid var(--border)', borderRadius: 'var(--radius)', overflow: 'hidden' },
  findingsScanHeader: { padding: '0.75rem 1rem', borderBottom: '1px solid var(--border)', background: 'var(--bg-subtle, #f8f8f8)' },
  findingsScanTitle: { margin: '0.25rem 0 0 0', fontSize: '1.1rem' },
  findingsTabs: { display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', background: 'var(--bg-subtle, #f8f8f8)' },
  findingsTab: {
    padding: '0.5rem 1rem',
    border: 'none',
    background: 'none',
    cursor: 'pointer',
    fontSize: '0.9rem',
    color: 'var(--text-muted)',
    borderBottom: '2px solid transparent',
  },
  findingsTabActive: { color: 'var(--text)', fontWeight: 600, borderBottomColor: 'var(--primary)' },
  findingsContent: { padding: '1rem' },
  findingsToolbar: { display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' },
  findingsSearch: {
    flex: '1',
    maxWidth: 320,
    padding: '0.5rem 0.75rem',
    borderRadius: 'var(--radius)',
    border: '1px solid var(--border)',
    fontSize: '0.9rem',
  },
  findingsCount: { fontSize: '0.9rem', color: 'var(--text-muted)' },
  findingsVulnLayout: { display: 'grid', gridTemplateColumns: '1fr 220px', gap: '1.5rem', alignItems: 'start' },
  findingsTableWrap: { overflowX: 'auto', minWidth: 0 },
  findingsTable: { width: '100%', borderCollapse: 'collapse' },
  findingsTh: {
    textAlign: 'left',
    padding: '0.5rem 0.75rem',
    borderBottom: '1px solid var(--border)',
    fontSize: '0.85rem',
    fontWeight: 600,
    color: 'var(--text-muted)',
  },
  findingsTd: { padding: '0.75rem 0.85rem', borderBottom: '1px solid var(--border)', fontSize: '0.9rem', verticalAlign: 'middle' },
  findingsTdName: { padding: '0.75rem 0.85rem', borderBottom: '1px solid var(--border)', fontSize: '0.9rem', maxWidth: 420, verticalAlign: 'middle' },
  findingsTr: { cursor: 'pointer', transition: 'background 0.15s' },
  findingsTrHover: {},
  severityBadge: {
    display: 'inline-block',
    padding: '0.2rem 0.5rem',
    borderRadius: 4,
    fontSize: '0.75rem',
    fontWeight: 600,
  },
  findingsSummary: { padding: '1rem', border: '1px solid var(--border)', borderRadius: 'var(--radius)', maxWidth: 240 },
  findingsSummaryTitle: { margin: '0 0 0.5rem 0', fontSize: '0.9rem' },
  findingsSummaryList: { display: 'flex', flexDirection: 'column', gap: '0.35rem' },
  findingsSummaryRow: { display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' },
  severityDot: { width: 8, height: 8, borderRadius: '50%', flexShrink: 0 },
  findingsSummaryCount: { marginLeft: 'auto', fontWeight: 600 },
  findingsDetailRoot: { border: '1px solid var(--border)', borderRadius: 'var(--radius)', overflow: 'hidden' },
  findingsDetailHeader: { padding: '0.75rem 1rem', borderBottom: '1px solid var(--border)', background: 'var(--bg-subtle, #f8f8f8)' },
  findingsDetailBreadcrumb: { fontSize: '0.85rem', color: 'var(--text-muted)', marginLeft: '0.5rem' },
  findingsDetailLayout: { display: 'grid', gridTemplateColumns: '1fr 280px', gap: '1.5rem', padding: '1rem', minHeight: 0 },
  findingsDetailMain: { minWidth: 0 },
  findingsDetailTitleRow: { display: 'flex', alignItems: 'flex-start', gap: '0.75rem', marginBottom: '0.5rem' },
  findingsDetailTitle: { margin: 0, fontSize: '1rem', fontWeight: 600, flex: 1 },
  findingsSynopsis: { margin: '0 0 1rem 0', fontSize: '0.9rem', color: 'var(--text-muted)' },
  findingsSection: { marginTop: '1.25rem' },
  findingsSectionTitle: { margin: '0 0 0.35rem 0', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)' },
  findingsSectionBody: { fontSize: '0.9rem' },
  findingsSidebar: { borderLeft: '1px solid var(--border)', paddingLeft: '1rem' },
  findingsSidebarBlock: {},
  findingsSidebarTitle: { margin: '0 0 0.5rem 0', fontSize: '0.9rem', fontWeight: 600 },
  findingsSidebarDl: { margin: 0, fontSize: '0.85rem' },
  findingsSidebarDt: { marginTop: '0.5rem', color: 'var(--text-muted)' },
  findingsSidebarDd: { margin: '0.25rem 0 0 0' },
  hostVulnCard: { marginBottom: '1.5rem', padding: '1rem', border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--surface, #fff)' },
  hostVulnName: { fontWeight: 600, marginRight: '0.5rem' },
  hostVulnSynopsis: { margin: '0.25rem 0', fontSize: '0.9rem', color: 'var(--text-muted)' },
  hostPluginRow: { display: 'flex', alignItems: 'center', gap: '0.35rem', marginBottom: '0.4rem', fontSize: '0.85rem' },
  hostPluginId: { fontFamily: 'var(--font-mono)', marginRight: '0.25rem' },
}
