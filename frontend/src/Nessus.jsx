import { useState, useEffect, useCallback } from 'react'
import { api } from './api'

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_LABELS  = ['Info', 'Low', 'Medium', 'High', 'Critical']
const SEV_COLORS  = {
  4: { bg: 'rgba(220,38,38,0.12)',  text: '#f87171', border: 'rgba(220,38,38,0.3)'  }, // Critical
  3: { bg: 'rgba(234,88,12,0.12)',  text: '#fb923c', border: 'rgba(234,88,12,0.3)'  }, // High
  2: { bg: 'rgba(217,119,6,0.12)',  text: '#fbbf24', border: 'rgba(217,119,6,0.3)'  }, // Medium
  1: { bg: 'rgba(37,99,235,0.10)',  text: '#60a5fa', border: 'rgba(37,99,235,0.25)' }, // Low
  0: { bg: 'rgba(100,116,139,0.1)', text: '#94a3b8', border: 'rgba(100,116,139,0.2)'}, // Info
}

function sevLabel(s) {
  const n = Number(s)
  return SEV_LABELS[n] ?? String(s ?? 'Info')
}

function SeverityPill({ severity, size = 'sm' }) {
  const n = Number(severity ?? 0)
  const cfg = SEV_COLORS[n] || SEV_COLORS[0]
  return (
    <span style={{
      display: 'inline-block',
      padding: size === 'lg' ? '3px 12px' : '2px 8px',
      borderRadius: 4,
      fontSize: size === 'lg' ? '0.8rem' : '0.72rem',
      fontWeight: 700,
      letterSpacing: '0.04em',
      textTransform: 'uppercase',
      background: cfg.bg,
      color: cfg.text,
      border: `1px solid ${cfg.border}`,
      whiteSpace: 'nowrap',
    }}>
      {sevLabel(n)}
    </span>
  )
}

function formatStatus(s) {
  if (!s) return 'Unknown'
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase()
}

function formatLastRun(ts) {
  if (!ts) return 'Never'
  try { return new Date(ts * 1000).toLocaleString() } catch { return String(ts) }
}

function StatusChip({ status }) {
  const s = (status || '').toLowerCase()
  const cfg = s === 'completed'  ? { bg: 'rgba(5,150,105,0.12)',  text: '#34d399' }
            : s === 'running'    ? { bg: 'rgba(79,70,229,0.12)',   text: '#818cf8' }
            : s === 'paused'     ? { bg: 'rgba(217,119,6,0.12)',   text: '#fbbf24' }
            : s === 'canceled'   ? { bg: 'rgba(100,116,139,0.1)',  text: '#94a3b8' }
            :                      { bg: 'rgba(100,116,139,0.1)',  text: '#94a3b8' }
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: '0.75rem',
      fontWeight: 600,
      background: cfg.bg,
      color: cfg.text,
    }}>
      {formatStatus(status)}
    </span>
  )
}

// ── Vuln detail panel ─────────────────────────────────────────────────────────

function VulnDetail({ vuln, onBack, scanName }) {
  if (!vuln) return null
  return (
    <div style={S.detailRoot}>
      <div style={S.detailNav}>
        <button type="button" style={S.backBtn} onClick={onBack}>← Back</button>
        <span style={S.detailBreadcrumb}>{scanName} / Plugin #{vuln.plugin_id}</span>
      </div>

      <div style={S.detailLayout}>
        {/* Main content */}
        <div style={S.detailMain}>
          <div style={S.detailTitleRow}>
            <SeverityPill severity={vuln.severity} size="lg" />
            <h2 style={S.detailTitle}>{vuln.plugin_name || `Plugin ${vuln.plugin_id}`}</h2>
          </div>

          {vuln.synopsis && <p style={S.synopsis}>{vuln.synopsis}</p>}

          {vuln.description && (
            <Section title="Description">
              <pre style={S.preBlock}>{vuln.description}</pre>
            </Section>
          )}

          {vuln.solution && (
            <Section title="Solution">
              <pre style={S.preBlock}>{vuln.solution}</pre>
            </Section>
          )}

          {vuln.plugin_output && (
            <Section title="Plugin Output">
              <pre style={S.termBlock}>{vuln.plugin_output}</pre>
            </Section>
          )}

          {(vuln.affected_hosts?.length > 0 || vuln.affected_count > 0) && (
            <Section title={`Affected Hosts (${vuln.affected_count ?? vuln.affected_hosts?.length ?? 0})`}>
              <div style={S.chipGroup}>
                {(vuln.affected_hosts || []).map((h, i) => (
                  <span key={i} style={S.hostChip}>{h}</span>
                ))}
              </div>
            </Section>
          )}
        </div>

        {/* Sidebar */}
        <aside style={S.detailSidebar}>
          <div style={S.sidebarCard}>
            <h4 style={S.sidebarTitle}>Plugin Details</h4>
            <dl style={S.dl}>
              <dt style={S.dt}>Severity</dt>
              <dd style={S.dd}><SeverityPill severity={vuln.severity} /></dd>
              <dt style={S.dt}>Plugin ID</dt>
              <dd style={S.dd}><code style={S.mono}>{vuln.plugin_id}</code></dd>
              {vuln.port && <><dt style={S.dt}>Port</dt><dd style={S.dd}>{vuln.port}/{vuln.protocol || 'tcp'}</dd></>}
              {vuln.risk_factor && <><dt style={S.dt}>Risk Factor</dt><dd style={S.dd}>{vuln.risk_factor}</dd></>}
              {vuln.cvss_score && <><dt style={S.dt}>CVSS</dt><dd style={S.dd}>{vuln.cvss_score}</dd></>}
              {vuln.cve && <><dt style={S.dt}>CVE</dt><dd style={S.dd}><code style={S.mono}>{vuln.cve}</code></dd></>}
            </dl>
          </div>
        </aside>
      </div>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <section style={S.section}>
      <h3 style={S.sectionTitle}>{title}</h3>
      {children}
    </section>
  )
}

// ── Imported scan findings view ───────────────────────────────────────────────

function ImportFindings({ projectId, importMeta, onBack }) {
  const [detail, setDetail]       = useState(null)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [subView, setSubView]     = useState('vulns') // 'vulns' | 'hosts'
  const [search, setSearch]       = useState('')
  const [selectedVuln, setSelectedVuln] = useState(null)

  useEffect(() => {
    setLoading(true)
    api.nessus.getImport(projectId, importMeta.scan_id)
      .then(setDetail)
      .catch((e) => setError(e?.body?.detail || e?.message || 'Failed to load'))
      .finally(() => setLoading(false))
  }, [projectId, importMeta.scan_id])

  if (loading) return <div style={S.muted}>Loading scan details…</div>
  if (error)   return <div style={S.errorBox}>{error}</div>
  if (!detail) return null

  if (selectedVuln) {
    return (
      <VulnDetail
        vuln={selectedVuln}
        scanName={detail.scan_name || `Scan ${importMeta.scan_id}`}
        onBack={() => setSelectedVuln(null)}
      />
    )
  }

  // Build unified vuln list (deduplicated by plugin_id) with host lists
  const vulnMap = new Map()
  for (const host of detail.hosts || []) {
    for (const v of host.vulns || []) {
      const key = v.plugin_id
      if (!vulnMap.has(key)) {
        vulnMap.set(key, { ...v, affected_hosts: [], affected_count: 0 })
      }
      const existing = vulnMap.get(key)
      existing.affected_hosts.push(host.name || host.host_ip)
      existing.affected_count = existing.affected_hosts.length
    }
  }
  const allVulns = [...vulnMap.values()].sort((a, b) => Number(b.severity) - Number(a.severity))

  const filtered = search.trim()
    ? allVulns.filter(v => (v.plugin_name || '').toLowerCase().includes(search.toLowerCase()))
    : allVulns

  const sevCounts = [0, 1, 2, 3, 4].map(n => ({
    n, label: SEV_LABELS[n], count: allVulns.filter(v => Number(v.severity) === n).length
  })).reverse().filter(x => x.count > 0)

  const hosts = detail.hosts || []

  return (
    <div>
      {/* Back + scan name */}
      <div style={S.findingsHeader}>
        <button type="button" style={S.backBtn} onClick={onBack}>← All scans</button>
        <span style={S.findingsScanName}>{detail.scan_name || `Scan ${importMeta.scan_id}`}</span>
      </div>

      {/* Sub-tabs */}
      <div style={S.subTabs}>
        <button
          type="button"
          style={{ ...S.subTab, ...(subView === 'vulns' ? S.subTabActive : {}) }}
          onClick={() => setSubView('vulns')}
        >
          Vulnerabilities {allVulns.length > 0 && <span style={S.tabCount}>{allVulns.length}</span>}
        </button>
        <button
          type="button"
          style={{ ...S.subTab, ...(subView === 'hosts' ? S.subTabActive : {}) }}
          onClick={() => setSubView('hosts')}
        >
          Hosts {hosts.length > 0 && <span style={S.tabCount}>{hosts.length}</span>}
        </button>
      </div>

      {subView === 'vulns' && (
        <div style={S.findingsBody}>
          {/* Toolbar */}
          <div style={S.toolbar}>
            <input
              type="search"
              placeholder="Search vulnerabilities…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={S.searchInput}
            />
            <span style={S.muted}>{filtered.length} vulnerabilities</span>
          </div>

          <div style={S.findingsTwoPan}>
            {/* Vuln table */}
            <div style={S.vulnTableWrap}>
              <table style={S.table}>
                <thead>
                  <tr>
                    <th style={S.th}>Sev</th>
                    <th style={S.th}>Name</th>
                    <th style={{ ...S.th, textAlign: 'right' }}>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr><td colSpan={3} style={S.td}>No vulnerabilities found.</td></tr>
                  ) : filtered.map((v, i) => (
                    <tr
                      key={v.plugin_id ?? i}
                      style={S.vulnRow}
                      onClick={() => setSelectedVuln(v)}
                    >
                      <td style={{ ...S.td, width: 90 }}><SeverityPill severity={v.severity} /></td>
                      <td style={{ ...S.td, ...S.vulnName }}>{v.plugin_name || `Plugin ${v.plugin_id}`}</td>
                      <td style={{ ...S.td, textAlign: 'right', color: 'var(--text-muted)' }}>{v.affected_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Severity summary */}
            <div style={S.sevSummary}>
              <div style={S.sevSummaryTitle}>By severity</div>
              {sevCounts.map(({ n, label, count }) => {
                const cfg = SEV_COLORS[n] || SEV_COLORS[0]
                return (
                  <div key={n} style={S.sevRow}>
                    <span style={{ ...S.sevDot, background: cfg.text }} />
                    <span style={S.sevLabel}>{label}</span>
                    <span style={S.sevCount}>{count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {subView === 'hosts' && (
        <div style={S.findingsBody}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Host</th>
                <th style={{ ...S.th, textAlign: 'right' }}>Findings</th>
              </tr>
            </thead>
            <tbody>
              {hosts.length === 0 ? (
                <tr><td colSpan={2} style={S.td}>No hosts.</td></tr>
              ) : hosts.map((h, i) => (
                <tr key={h.host_ip || i} style={S.vulnRow} onClick={() => {
                  // Show all vulns for this host
                  setSubView('vulns')
                  setSearch(h.name || h.host_ip || '')
                }}>
                  <td style={{ ...S.td, ...S.mono }}>{h.name || h.host_ip}</td>
                  <td style={{ ...S.td, textAlign: 'right', color: 'var(--text-muted)' }}>
                    {(h.vulns || []).length}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Imported scan list ────────────────────────────────────────────────────────

function ImportedResults({ projectId, imports, onDelete, onRefresh }) {
  const [selected, setSelected] = useState(null)

  if (selected) {
    return (
      <ImportFindings
        projectId={projectId}
        importMeta={selected}
        onBack={() => setSelected(null)}
      />
    )
  }

  if (!imports.length) {
    return (
      <div style={S.emptyBox}>
        <p style={S.emptyTitle}>No imported results yet</p>
        <p style={S.muted}>Switch to <strong>Available scans</strong> and click <strong>Import results</strong> after a scan completes.</p>
      </div>
    )
  }

  return (
    <div>
      <table style={S.table}>
        <thead>
          <tr>
            <th style={S.th}>Scan name</th>
            <th style={S.th}>Hosts</th>
            <th style={S.th}>Findings</th>
            <th style={S.th}>Imported</th>
            <th style={S.th}></th>
          </tr>
        </thead>
        <tbody>
          {imports.map((imp) => (
            <tr
              key={imp.scan_id}
              style={S.vulnRow}
              onClick={() => setSelected(imp)}
            >
              <td style={{ ...S.td, fontWeight: 500 }}>{imp.scan_name || `Scan ${imp.scan_id}`}</td>
              <td style={S.td}>{imp.hosts_count ?? 0}</td>
              <td style={S.td}>{imp.vulns_count ?? 0}</td>
              <td style={{ ...S.td, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                {imp.imported_at ? new Date(imp.imported_at).toLocaleString() : '—'}
              </td>
              <td style={S.td} onClick={e => e.stopPropagation()}>
                <button
                  type="button"
                  style={S.dangerBtn}
                  onClick={() => {
                    if (window.confirm('Remove this imported scan?')) onDelete(imp.scan_id)
                  }}
                >
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Available scans (scan management) ────────────────────────────────────────

function AvailableScans({ projectId, scans, webLaunchInfo, launching, pausing, stopping, importing, deleting, templates,
  onLaunch, onPause, onStop, onImport, onDelete, showCreate, setShowCreate, handleShowCreateToggle, createName, setCreateName, createTemplateUuid, setCreateTemplateUuid,
  createExtraTargets, setCreateExtraTargets, creating, creatingViaWeb,
  createError, onCreateAPI, onCreateWeb
}) {
  return (
    <div>
      {/* Scan table */}
      {scans.length === 0 ? (
        <div style={S.emptyBox}>
          <p style={S.muted}>No scans found. Create one below or directly in Nessus, then refresh.</p>
        </div>
      ) : (
        <div style={S.tableWrap}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Name</th>
                <th style={S.th}>Status</th>
                <th style={S.th}>Last run</th>
                <th style={{ ...S.th, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s, idx) => {
                const key = s.id ?? s.name ?? idx
                const name = s.name ?? `Scan ${s.id}`
                const isLaunching = launching === key
                const isPausing   = pausing   === name
                const isStopping  = stopping  === name
                const isImporting = importing === s.id
                const isDeleting  = deleting  === key
                const status = (s.status || '').toLowerCase()
                const isRunning = status === 'running'
                const isPaused  = status === 'paused'
                const canPause  = isRunning && webLaunchInfo?.available
                const canStop   = (isRunning || isPaused) && webLaunchInfo?.available
                return (
                  <tr key={key} style={S.scanRow}>
                    <td style={{ ...S.td, fontWeight: 500 }}>{name}</td>
                    <td style={S.td}><StatusChip status={s.status} /></td>
                    <td style={{ ...S.td, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                      {formatLastRun(s.last_modification_date)}
                    </td>
                    <td style={{ ...S.td, textAlign: 'right' }}>
                      <div style={S.actionGroup}>
                        {/* Launch — hidden when scan is currently running or paused */}
                        {!isRunning && !isPaused && (
                          <button
                            type="button"
                            style={{ ...S.actionBtn, ...S.primaryBtn }}
                            disabled={isLaunching || (!webLaunchInfo?.available && !s.id)}
                            title={!webLaunchInfo?.available ? 'Configure Tenable credentials for web launch' : ''}
                            onClick={() => onLaunch(s.id, name)}
                          >
                            {isLaunching ? 'Launching…' : 'Launch'}
                          </button>
                        )}

                        {/* Pause — only when running */}
                        {canPause && (
                          <button
                            type="button"
                            style={S.actionBtn}
                            disabled={isPausing}
                            onClick={() => onPause(name)}
                          >
                            {isPausing ? 'Pausing…' : 'Pause'}
                          </button>
                        )}

                        {/* Resume — only when paused (resume = relaunch) */}
                        {isPaused && webLaunchInfo?.available && (
                          <button
                            type="button"
                            style={{ ...S.actionBtn, ...S.primaryBtn }}
                            disabled={isLaunching}
                            onClick={() => onLaunch(s.id, name)}
                          >
                            {isLaunching ? 'Resuming…' : 'Resume'}
                          </button>
                        )}

                        {/* Stop — when running or paused */}
                        {canStop && (
                          <button
                            type="button"
                            style={{ ...S.actionBtn, ...S.dangerOutlineBtn }}
                            disabled={isStopping}
                            onClick={() => onStop(name)}
                          >
                            {isStopping ? 'Stopping…' : 'Stop'}
                          </button>
                        )}

                        {/* Open in Nessus */}
                        {webLaunchInfo?.open_url && (
                          <button
                            type="button"
                            style={S.actionBtn}
                            onClick={() => window.open(webLaunchInfo.open_url, '_blank', 'noopener,noreferrer')}
                          >
                            Open in Nessus ↗
                          </button>
                        )}

                        {/* Import */}
                        <button
                          type="button"
                          style={S.actionBtn}
                          disabled={isImporting || !s.id}
                          onClick={() => onImport(s.id)}
                        >
                          {isImporting ? 'Importing…' : 'Import results'}
                        </button>

                        {/* Trash */}
                        {webLaunchInfo?.available && (
                          <button
                            type="button"
                            style={{ ...S.actionBtn, ...S.dangerOutlineBtn }}
                            disabled={isDeleting}
                            onClick={() => onDelete(s.id, name)}
                          >
                            {isDeleting ? 'Deleting…' : 'Trash'}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Create scan section */}
      <div style={S.createSection}>
        <button
          type="button"
          style={S.toggleCreateBtn}
          onClick={() => handleShowCreateToggle()}
        >
          {showCreate ? 'Hide create scan' : '+ Create new scan'}
        </button>

        {showCreate && (
          <div style={S.createForm}>
            {createError && <div style={S.errorBox}>{createError}</div>}

            <div style={S.formRow}>
              <label style={S.label}>Scan name</label>
              <input
                type="text"
                value={createName}
                onChange={e => setCreateName(e.target.value)}
                placeholder="e.g. ForSight scan"
                style={S.input}
              />
            </div>

            <div style={S.formRow}>
              <label style={S.label}>Template</label>
              <select
                value={createTemplateUuid}
                onChange={e => setCreateTemplateUuid(e.target.value)}
                style={S.input}
              >
                <option value="">— Select template —</option>
                {templates.map((t, i) => {
                  // templates-web returns {title, category}; templates (API) returns {uuid, title|name}
                  const value = t.uuid || t.title || t.name || `tpl-${i}`
                  const label = t.title || t.name || value
                  const cat   = t.category ? ` (${t.category})` : ''
                  return (
                    <option key={value + i} value={value}>
                      {label}{cat}
                    </option>
                  )
                })}
              </select>
            </div>

            <div style={S.formRow}>
              <label style={S.label}>Extra targets (optional)</label>
              <textarea
                value={createExtraTargets}
                onChange={e => setCreateExtraTargets(e.target.value)}
                placeholder="Additional IPs or hostnames"
                style={{ ...S.input, minHeight: 72, resize: 'vertical' }}
              />
            </div>

            <div style={S.formActions}>
              <button
                type="button"
                style={{ ...S.actionBtn, ...S.primaryBtn }}
                disabled={creating || !createName.trim() || !createTemplateUuid}
                onClick={onCreateAPI}
              >
                {creating ? 'Creating…' : 'Create scan (API)'}
              </button>
              {webLaunchInfo?.available && (
                <button
                  type="button"
                  style={S.actionBtn}
                  disabled={creatingViaWeb || !createName.trim()}
                  onClick={onCreateWeb}
                >
                  {creatingViaWeb ? 'Creating…' : 'Create via web'}
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Nessus component ─────────────────────────────────────────────────────

export default function Nessus({ projectId, onRefresh }) {
  const [configured,    setConfigured]    = useState(false)
  const [webLaunchInfo, setWebLaunchInfo] = useState(null)
  const [scans,         setScans]         = useState([])
  const [imports,       setImports]       = useState([])
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [view,          setView]          = useState('imported') // 'imported' | 'scans'
  const [launching,     setLaunching]     = useState(null)
  const [pausing,       setPausing]       = useState(null)
  const [stopping,      setStopping]      = useState(null)
  const [importing,     setImporting]     = useState(null)
  const [deleting,      setDeleting]      = useState(null)
  const [templates,     setTemplates]     = useState([])
  const [showCreate,    setShowCreate]    = useState(false)
  const [createName,    setCreateName]    = useState('')
  const [createTemplateUuid, setCreateTemplateUuid] = useState('')
  const [createExtraTargets, setCreateExtraTargets] = useState('')
  const [creating,      setCreating]      = useState(false)
  const [creatingViaWeb,setCreatingViaWeb]= useState(false)
  const [createError,   setCreateError]   = useState(null)
  const [statusMsg,     setStatusMsg]     = useState(null) // { type, text }

  const flash = (type, text) => {
    setStatusMsg({ type, text })
    setTimeout(() => setStatusMsg(null), 6000)
  }

  const loadImports = useCallback(() => {
    if (!projectId || !configured) return Promise.resolve()
    return api.nessus.listImports(projectId)
      .then(d => setImports(Array.isArray(d?.scans) ? d.scans : []))
      .catch(() => {})
  }, [projectId, configured])

  const loadScans = useCallback((bust = false) => {
    if (!projectId || !configured) return Promise.resolve()
    return api.nessus.listScans(projectId, bust)
      .then(d => setScans(Array.isArray(d?.scans) ? d.scans : []))
      .catch(() => {})
  }, [projectId, configured])

  // Initial data load
  useEffect(() => {
    if (!projectId) return
    api.nessus.configured()
      .then(r => setConfigured(r?.configured === true))
      .catch(() => setConfigured(false))
  }, [projectId])

  useEffect(() => {
    if (!configured) { setLoading(false); return }
    api.nessus.webLaunchAvailable().then(setWebLaunchInfo).catch(() => {})
    setLoading(true)
    Promise.all([
      api.nessus.listScans(projectId).then(d => Array.isArray(d?.scans) ? d.scans : []),
      api.nessus.listImports(projectId).then(d => Array.isArray(d?.scans) ? d.scans : []),
      // Use templates-web (Selenium scrape) when web launch is configured — names match Nessus exactly.
      // Fallback to API templates list otherwise.
      Promise.resolve([]),
    ])
      .then(([s, i, t]) => { setScans(s); setImports(i); setTemplates(t) })
      .catch(e => setError(e?.body?.detail || e?.message || 'Failed to load Nessus data'))
      .finally(() => setLoading(false))
  }, [configured, projectId])

  const handleRefresh = () => {
    loadImports()
    loadScans(true)
  }

  const handleShowCreateToggle = async () => {
  const opening = !showCreate
  setShowCreate(v => !v)
  if (opening && templates.length === 0) {
    try {
      const t = await api.nessus.templatesViaWeb(projectId)
      setTemplates(Array.isArray(t?.templates) ? t.templates : [])
    } catch {
      // silently fail — user can still type a template name manually
    }
  }


  const handleLaunch = async (scanId, scanName) => {
    const key = scanId ?? scanName
    setLaunching(key)
    try {
      if (webLaunchInfo?.available) {
        await api.nessus.launchScanViaWebByName(projectId, scanName)
        flash('success', `Launch triggered for "${scanName}".`)
      } else if (scanId) {
        await api.nessus.launchScan(projectId, scanId, { use_project_targets: true })
        flash('success', `Scan launched.`)
      } else {
        flash('error', 'Web launch not configured. Set FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD in .env.')
      }
      await loadScans(true)
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Launch failed.')
    } finally {
      setLaunching(null)
    }
  }

  const handlePause = async (scanName) => {
    setPausing(scanName)
    try {
      await api.nessus.pauseScanViaWebByName(projectId, scanName)
      flash('success', `Paused "${scanName}".`)
      await loadScans(true)
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Pause failed.')
    } finally {
      setPausing(null)
    }
  }

  const handleStop = async (scanName) => {
    if (!window.confirm(`Stop scan "${scanName}"? In-progress results will be saved.`)) return
    setStopping(scanName)
    try {
      await api.nessus.stopScanViaWebByName(projectId, scanName)
      flash('success', `Stopped "${scanName}".`)
      await loadScans(true)
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Stop failed.')
    } finally {
      setStopping(null)
    }
  }

  const handleImport = async (scanId) => {
    setImporting(scanId)
    try {
      await api.nessus.importScan(projectId, scanId)
      flash('success', 'Import complete. Results merged into Hosts.')
      await loadImports()
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Import failed.')
    } finally {
      setImporting(null)
    }
  }

  const handleDelete = async (scanId, scanName) => {
    if (!window.confirm(`Delete scan "${scanName}" from Nessus?`)) return
    const key = scanId ?? scanName
    setDeleting(key)
    try {
      await api.nessus.deleteScanViaWebByName(projectId, scanName)
      flash('success', `Scan "${scanName}" deleted.`)
      await loadScans(true)
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Delete failed.')
    } finally {
      setDeleting(null)
    }
  }

  const handleDeleteImport = async (scanId) => {
    try {
      await api.nessus.deleteImport(projectId, scanId)
      await loadImports()
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Remove failed.')
    }
  }

  const handleCreateAPI = async () => {
    if (!createName.trim() || !createTemplateUuid) return
    setCreating(true); setCreateError(null)
    try {
      await api.nessus.createScan(projectId, {
        name: createName.trim(),
        template_uuid: createTemplateUuid,
        use_project_targets: true,
        text_targets: createExtraTargets || undefined,
      })
      flash('success', `Scan "${createName}" created.`)
      setCreateName(''); setCreateTemplateUuid(''); setCreateExtraTargets(''); setShowCreate(false)
      await loadScans(true)
    } catch (e) {
      setCreateError(e?.body?.detail || e?.message || 'Create failed.')
    } finally {
      setCreating(false)
    }
  }

  const handleCreateWeb = async () => {
    if (!createName.trim()) return
    setCreatingViaWeb(true); setCreateError(null)
    try {
      // Use selected template title as the template_key (matched by substring on Nessus side)
      await api.nessus.createScanViaWeb(projectId, {
        name: createName.trim(),
        template_key: createTemplateUuid || 'advanced',
        use_project_targets: true,
        text_targets: createExtraTargets || undefined,
      })
      flash('success', `Scan "${createName}" created via web.`)
      setCreateName(''); setCreateExtraTargets(''); setShowCreate(false)
      await loadScans(true)
    } catch (e) {
      setCreateError(e?.body?.detail || e?.message || 'Create via web failed.')
    } finally {
      setCreatingViaWeb(false)
    }
  }

  // ── Not configured ─────────────────────────────────────────────────────────
  if (!configured && !loading) {
    return (
      <div style={S.notConfigured}>
        <h2 style={S.notConfiguredTitle}>Nessus not configured</h2>
        <p style={S.muted}>
          Set Tenable credentials in <code style={S.inlineCode}>backend/.env</code>:
        </p>
        <ul style={S.configList}>
          {[
            ['FORSIGHT_TENABLE_BASE_URL', 'Nessus URL (default https://127.0.0.1:8834)'],
            ['FORSIGHT_TENABLE_ACCESS_KEY', 'API access key'],
            ['FORSIGHT_TENABLE_SECRET_KEY', 'API secret key'],
            ['FORSIGHT_TENABLE_USERNAME',   'Username (for Selenium launch/create/delete)'],
            ['FORSIGHT_TENABLE_PASSWORD',   'Password (for Selenium)'],
          ].map(([k, v]) => (
            <li key={k} style={S.configItem}>
              <code style={S.inlineCode}>{k}</code>
              <span style={S.muted}> — {v}</span>
            </li>
          ))}
        </ul>
      </div>
    )
  }

  if (loading && !imports.length) {
    return <div style={S.muted}>Loading Nessus data…</div>
  }

  // ── Main layout ─────────────────────────────────────────────────────────────
  return (
    <div>
      {/* Header bar */}
      <div style={S.header}>
        <h2 style={S.pageTitle}>Nessus</h2>
        <div style={S.headerActions}>
          <button
            type="button"
            style={{ ...S.tabPill, ...(view === 'imported' ? S.tabPillActive : {}) }}
            onClick={() => setView('imported')}
          >
            Imported results
          </button>
          <button
            type="button"
            style={{ ...S.tabPill, ...(view === 'scans' ? S.tabPillActive : {}) }}
            onClick={() => setView('scans')}
          >
            Available scans
          </button>
          <button type="button" style={S.refreshBtn} onClick={handleRefresh}>
            ↻ Refresh
          </button>
        </div>
      </div>

      {/* Status flash message */}
      {statusMsg && (
        <div style={{
          ...S.flashMsg,
          borderLeftColor: statusMsg.type === 'success' ? 'var(--primary)' : 'var(--danger)',
          color: statusMsg.type === 'success' ? 'var(--primary)' : 'var(--danger)',
        }}>
          {statusMsg.text}
        </div>
      )}

      {error && <div style={S.errorBox}>{error}</div>}

      {/* Content */}
      <div style={S.content}>
        {view === 'imported' && (
          <ImportedResults
            projectId={projectId}
            imports={imports}
            onDelete={handleDeleteImport}
            onRefresh={handleRefresh}
          />
        )}

        {view === 'scans' && (
          <AvailableScans
            projectId={projectId}
            scans={scans}
            webLaunchInfo={webLaunchInfo}
            launching={launching}
            pausing={pausing}
            stopping={stopping}
            importing={importing}
            deleting={deleting}
            templates={templates}
            onLaunch={handleLaunch}
            onPause={handlePause}
            onStop={handleStop}
            onImport={handleImport}
            onDelete={handleDelete}
            showCreate={showCreate}
            setShowCreate={setShowCreate}
            handleShowCreateToggle={handleShowCreateToggle}
            createName={createName}
            setCreateName={setCreateName}
            createTemplateUuid={createTemplateUuid}
            setCreateTemplateUuid={setCreateTemplateUuid}
            createExtraTargets={createExtraTargets}
            setCreateExtraTargets={setCreateExtraTargets}
            creating={creating}
            creatingViaWeb={creatingViaWeb}
            createError={createError}
            onCreateAPI={handleCreateAPI}
            onCreateWeb={handleCreateWeb}
          />
        )}
      </div>
    </div>
  )
}

// ── Styles ────────────────────────────────────────────────────────────────────

const S = {
  // Layout
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 16 },
  pageTitle: { margin: 0, fontSize: '1.25rem', fontWeight: 700 },
  headerActions: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
  content: {},

  // Tab pills
  tabPill: { padding: '5px 14px', borderRadius: 20, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: '0.85rem', cursor: 'pointer', fontWeight: 500 },
  tabPillActive: { background: 'var(--accent)', color: 'var(--accent-text)', borderColor: 'var(--accent)' },
  refreshBtn: { padding: '5px 12px', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: '0.82rem', borderRadius: 6, cursor: 'pointer' },

  // Flash
  flashMsg: { padding: '10px 14px', borderLeft: '3px solid', borderRadius: '0 6px 6px 0', background: 'var(--surface)', marginBottom: 12, fontSize: '0.875rem', fontWeight: 500 },
  errorBox: { padding: '10px 14px', background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: 6, color: 'var(--danger)', fontSize: '0.875rem', marginBottom: 12 },

  // Table
  tableWrap: { overflowX: 'auto', borderRadius: 8, border: '1px solid var(--border)' },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' },
  th: { padding: '10px 14px', textAlign: 'left', fontWeight: 600, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', background: 'var(--surface-muted)', borderBottom: '1px solid var(--border)' },
  td: { padding: '11px 14px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle', color: 'var(--text)' },
  vulnRow: { cursor: 'pointer', transition: 'background 0.1s' },
  scanRow: {},
  vulnName: { maxWidth: 460, overflow: 'hidden', textOverflow: 'ellipsis' },

  // Action buttons
  actionGroup: { display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end', flexWrap: 'wrap' },
  actionBtn: { padding: '4px 12px', borderRadius: 5, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.8rem', cursor: 'pointer', fontWeight: 500, whiteSpace: 'nowrap' },
  primaryBtn: { background: 'var(--primary)', color: 'var(--primary-text)', border: 'none' },
  dangerBtn: { padding: '3px 10px', border: '1px solid rgba(220,38,38,0.4)', background: 'transparent', color: 'var(--danger)', borderRadius: 5, fontSize: '0.78rem', cursor: 'pointer' },
  dangerOutlineBtn: { borderColor: 'rgba(220,38,38,0.4)', color: 'var(--danger)', background: 'transparent' },

  // Findings two-pane
  findingsHeader: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 },
  findingsScanName: { fontWeight: 600, fontSize: '1rem' },
  findingsBody: { marginTop: 16 },
  findingsTwoPan: { display: 'grid', gridTemplateColumns: '1fr 200px', gap: 20, alignItems: 'start' },
  vulnTableWrap: { overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 8 },
  toolbar: { display: 'flex', alignItems: 'center', gap: 14, marginBottom: 12 },
  searchInput: { flex: 1, maxWidth: 320, padding: '7px 11px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--surface-muted)', color: 'var(--text)', fontSize: '0.875rem' },

  // Severity summary
  sevSummary: { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 14 },
  sevSummaryTitle: { fontWeight: 600, fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: 10 },
  sevRow: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 },
  sevDot: { width: 8, height: 8, borderRadius: '50%', flexShrink: 0 },
  sevLabel: { flex: 1, fontSize: '0.85rem', color: 'var(--text)' },
  sevCount: { fontSize: '0.85rem', fontWeight: 600, color: 'var(--text)' },

  // Sub-tabs
  subTabs: { display: 'flex', gap: 0, borderBottom: '2px solid var(--border)', marginBottom: 0 },
  subTab: { padding: '8px 18px', background: 'none', border: 'none', borderBottom: '2px solid transparent', cursor: 'pointer', fontSize: '0.9rem', color: 'var(--text-muted)', fontWeight: 500, marginBottom: -2 },
  subTabActive: { color: 'var(--accent)', borderBottomColor: 'var(--accent)', fontWeight: 600 },
  tabCount: { marginLeft: 6, background: 'var(--border)', color: 'var(--text-muted)', borderRadius: 10, padding: '1px 7px', fontSize: '0.75rem', fontWeight: 600 },

  // Vuln detail
  detailRoot: { paddingBottom: 32 },
  detailNav: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 },
  detailBreadcrumb: { color: 'var(--text-muted)', fontSize: '0.85rem' },
  detailLayout: { display: 'grid', gridTemplateColumns: '1fr 240px', gap: 24, alignItems: 'start' },
  detailMain: {},
  detailTitleRow: { display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 12, flexWrap: 'wrap' },
  detailTitle: { margin: 0, fontSize: '1.2rem', fontWeight: 700, flex: 1 },
  synopsis: { color: 'var(--text-muted)', fontSize: '0.9rem', lineHeight: 1.55, marginBottom: 20 },
  section: { marginBottom: 20 },
  sectionTitle: { margin: '0 0 8px', fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' },
  preBlock: { margin: 0, padding: '12px 14px', background: 'var(--surface-muted)', border: '1px solid var(--border)', borderRadius: 6, fontSize: '0.82rem', lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text)', fontFamily: 'var(--font-mono)' },
  termBlock: { margin: 0, padding: '12px 14px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, fontSize: '0.78rem', lineHeight: 1.7, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text)', fontFamily: 'var(--font-mono)', maxHeight: 400, overflowY: 'auto' },
  chipGroup: { display: 'flex', flexWrap: 'wrap', gap: 6 },
  hostChip: { padding: '3px 10px', background: 'var(--surface-muted)', border: '1px solid var(--border)', borderRadius: 4, fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text)' },

  // Detail sidebar
  detailSidebar: {},
  sidebarCard: { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 14 },
  sidebarTitle: { margin: '0 0 12px', fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' },
  dl: { margin: 0 },
  dt: { fontSize: '0.72rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginTop: 10 },
  dd: { margin: '3px 0 0', fontSize: '0.85rem', color: 'var(--text)' },
  mono: { fontFamily: 'var(--font-mono)', fontSize: '0.82rem' },

  // Back button
  backBtn: { padding: '5px 12px', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', borderRadius: 5, fontSize: '0.82rem', cursor: 'pointer' },

  // Create form
  createSection: { marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)' },
  toggleCreateBtn: { padding: '6px 14px', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text)', borderRadius: 6, fontSize: '0.85rem', cursor: 'pointer' },
  createForm: { marginTop: 14, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 },
  formRow: { marginBottom: 14 },
  label: { display: 'block', fontWeight: 600, fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: 5 },
  input: { width: '100%', padding: '8px 11px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', color: 'var(--text)', fontSize: '0.9rem', fontFamily: 'inherit' },
  formActions: { display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 },

  // Empty / not-configured
  emptyBox: { padding: '32px 16px', textAlign: 'center' },
  emptyTitle: { fontWeight: 600, fontSize: '1rem', margin: '0 0 8px' },
  muted: { color: 'var(--text-muted)', fontSize: '0.875rem', lineHeight: 1.5, margin: 0 },
  notConfigured: { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 10, padding: 24 },
  notConfiguredTitle: { margin: '0 0 10px', fontSize: '1.1rem', fontWeight: 700 },
  configList: { paddingLeft: 20, lineHeight: 2, fontSize: '0.875rem' },
  configItem: {},
  inlineCode: { fontFamily: 'var(--font-mono)', fontSize: '0.82em', background: 'var(--surface-muted)', padding: '1px 5px', borderRadius: 3 },
}
