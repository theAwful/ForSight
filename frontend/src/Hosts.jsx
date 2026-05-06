import { useState, useEffect, useMemo } from 'react'
import { api } from './api'
import ConfirmModal from './ConfirmModal'

// ── Helpers ───────────────────────────────────────────────────────────────────

function findingLabel(f) {
  const name = f?.info?.name
  const template = f?.template
  if (name) return name
  if (template) return template.replace(/^[^/]+\//, '').replace(/[-_]/g, ' ')
  return 'Finding'
}

function findingSeverity(f) {
  const s = (f?.info?.severity || '').toLowerCase()
  return ['critical', 'high', 'medium', 'low', 'info'].includes(s) ? s : null
}

function sevStyle(s) {
  switch ((s || '').toLowerCase()) {
    case 'critical': return { bg: 'rgba(220,38,38,0.12)',  text: '#f87171', border: 'rgba(220,38,38,0.3)'  }
    case 'high':     return { bg: 'rgba(234,88,12,0.12)',  text: '#fb923c', border: 'rgba(234,88,12,0.3)'  }
    case 'medium':   return { bg: 'rgba(217,119,6,0.12)',  text: '#fbbf24', border: 'rgba(217,119,6,0.3)'  }
    case 'low':      return { bg: 'rgba(37,99,235,0.10)',  text: '#60a5fa', border: 'rgba(37,99,235,0.25)' }
    default:         return { bg: 'rgba(100,116,139,0.1)', text: '#94a3b8', border: 'rgba(100,116,139,0.2)'}
  }
}

function nessusSevLabel(n) {
  return ['Info', 'Low', 'Medium', 'High', 'Critical'][Number(n)] ?? String(n ?? 'Info')
}

function nessusSevStyle(n) {
  return sevStyle(nessusSevLabel(n).toLowerCase())
}

function SevPill({ label, size = 'sm' }) {
  const s = sevStyle(label)
  return (
    <span style={{
      display: 'inline-block',
      padding: size === 'lg' ? '3px 10px' : '2px 7px',
      borderRadius: 4,
      fontSize: size === 'lg' ? '0.78rem' : '0.68rem',
      fontWeight: 700,
      letterSpacing: '0.04em',
      textTransform: 'uppercase',
      background: s.bg, color: s.text, border: `1px solid ${s.border}`,
      whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  )
}

function hostSummary(h) {
  const ports   = h?.ports_detail?.length || h?.ports?.length || 0
  const byPort  = h?.by_port && typeof h.by_port === 'object' ? h.by_port : {}
  const shots   = Object.values(byPort).reduce((n, b) => n + (b.screenshots?.length || 0), 0)
  const nuclei  = Object.values(byPort).reduce((n, b) => n + (b.findings?.length   || 0), 0)
  const nessus  = h?.nessus_findings?.length || 0
  return { ports, shots, nuclei, nessus }
}

function riskDot(h) {
  const { nuclei, nessus } = hostSummary(h)
  if (nuclei > 0 || nessus > 0) return { color: '#f87171', label: 'Findings' }
  const ports = h?.ports_detail?.length || h?.ports?.length || 0
  if (ports >= 10) return { color: '#fbbf24', label: `${ports} ports` }
  if (ports > 0)   return { color: '#60a5fa', label: `${ports} ports` }
  return { color: 'var(--border)', label: 'No data' }
}

/** Build per-port rows merging nmap detail + by_port evidence */
function buildPortRows(host) {
  const byPort     = host?.by_port && typeof host.by_port === 'object' ? host.by_port : {}
  const detailMap  = new Map()
  for (const p of host.ports_detail || []) {
    const n = Number(p.port)
    if (!Number.isNaN(n)) detailMap.set(n, p)
  }
  const keys = Object.keys(byPort).sort((a, b) => (Number(a) || 0) - (Number(b) || 0))
  return keys.map(portKey => {
    const portNum   = Number(portKey)
    const detail    = !Number.isNaN(portNum) ? detailMap.get(portNum) : null
    const block     = byPort[portKey] || { screenshots: [], findings: [] }
    return { portKey, portNum, detail, screenshots: block.screenshots || [], findings: block.findings || [] }
  })
}

// ── Host detail panel ─────────────────────────────────────────────────────────

function HostDetail({ host, projectId, onExclude, onScreenshotClick }) {
  if (!host) return <div style={S.selectHint}>Select a host from the table.</div>

  const portRows   = buildPortRows(host)
  const nessus     = host.nessus_findings || []
  const dot        = riskDot(host)
  const { ports, shots, nuclei, nessusCount: _n } = { ...hostSummary(host), nessusCount: nessus.length }

  // All nmap-discovered ports (including those without by_port evidence)
  const allNmapPorts = host.ports_detail || []

  return (
    <div style={S.detailPanel}>
      {/* Host header */}
      <div style={S.detailHeader}>
        <div style={S.detailHeaderLeft}>
          <span style={{ ...S.riskDot, background: dot.color }} title={dot.label} />
          <h2 style={S.detailHostname}>{host.host}</h2>
        </div>
        <div style={S.detailHeaderActions}>
          <div style={S.statPills}>
            {ports > 0   && <span style={S.statPill}>{ports} ports</span>}
            {shots > 0   && <span style={S.statPill}>{shots} screenshots</span>}
            {nuclei > 0  && <span style={{ ...S.statPill, ...S.statPillWarn }}>{nuclei} Nuclei</span>}
            {nessus.length > 0 && <span style={{ ...S.statPill, ...S.statPillDanger }}>{nessus.length} Nessus</span>}
          </div>
          <button
            type="button"
            style={S.excludeBtn}
            onClick={() => onExclude(host.host)}
            title="Remove from list (out-of-scope)"
          >
            Remove from list
          </button>
        </div>
      </div>

      {/* Nothing at all */}
      {!portRows.length && !allNmapPorts.length && !nessus.length && (
        <p style={S.muted}>No ports, screenshots, or findings yet for this host.</p>
      )}

      {/* Open ports table (Nmap) */}
      {allNmapPorts.length > 0 && (
        <section style={S.section}>
          <h3 style={S.sectionTitle}>Open Ports</h3>
          <div style={S.tableWrap}>
            <table style={S.table}>
              <thead>
                <tr>
                  <th style={S.th}>Port</th>
                  <th style={S.th}>Protocol</th>
                  <th style={S.th}>Service</th>
                  <th style={S.th}>Product / Version</th>
                  <th style={S.th}>State</th>
                </tr>
              </thead>
              <tbody>
                {allNmapPorts.map((p, i) => (
                  <tr key={i}>
                    <td style={{ ...S.td, ...S.monoTd }}>{p.port}</td>
                    <td style={S.td}>{p.protocol || 'tcp'}</td>
                    <td style={S.td}>{p.service || '—'}</td>
                    <td style={S.td}>{[p.product, p.version].filter(Boolean).join(' ') || '—'}</td>
                    <td style={S.td}>{p.state || 'open'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Screenshots */}
      {portRows.some(r => r.screenshots.length > 0) && (
        <section style={S.section}>
          <h3 style={S.sectionTitle}>Screenshots</h3>
          <div style={S.screenshotGrid}>
            {portRows.flatMap(r => r.screenshots.map((s, i) => {
              const imgUrl = s.filename ? api.screenshots.url(projectId, s.filename) : ''
              return (
                <div key={`${r.portKey}-${i}`} style={S.screenshotCard}>
                  <button
                    type="button"
                    style={S.thumbBtn}
                    onClick={() => imgUrl && onScreenshotClick(imgUrl)}
                    title="Enlarge"
                  >
                    <img src={imgUrl} alt="" style={S.thumbImg} loading="lazy" />
                  </button>
                  <span style={S.thumbCaption} title={s.url || s.filename}>
                    {s.url || s.filename || `Port ${r.portKey}`}
                  </span>
                </div>
              )
            }))}
          </div>
        </section>
      )}

      {/* Nuclei findings */}
      {portRows.some(r => r.findings.length > 0) && (
        <section style={S.section}>
          <h3 style={S.sectionTitle}>Nuclei Findings</h3>
          <div style={S.tableWrap}>
            <table style={S.table}>
              <thead>
                <tr>
                  <th style={S.th}>Severity</th>
                  <th style={S.th}>Name</th>
                  <th style={S.th}>Port</th>
                  <th style={S.th}>Template</th>
                </tr>
              </thead>
              <tbody>
                {portRows.flatMap(r =>
                  r.findings.map((f, i) => {
                    const sev = findingSeverity(f)
                    return (
                      <tr key={`${r.portKey}-${i}`}>
                        <td style={S.td}>
                          {sev ? <SevPill label={sev} /> : <span style={S.muted}>—</span>}
                        </td>
                        <td style={S.td}>{findingLabel(f)}</td>
                        <td style={{ ...S.td, ...S.monoTd }}>{r.portKey === '0' ? '—' : r.portKey}</td>
                        <td style={{ ...S.td, ...S.monoTd, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {f?.template || '—'}
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Nessus findings */}
      {nessus.length > 0 && (
        <section style={S.section}>
          <h3 style={S.sectionTitle}>Nessus Findings</h3>
          <div style={S.tableWrap}>
            <table style={S.table}>
              <thead>
                <tr>
                  <th style={S.th}>Severity</th>
                  <th style={S.th}>Name</th>
                  <th style={S.th}>Port</th>
                  <th style={S.th}>Synopsis</th>
                </tr>
              </thead>
              <tbody>
                {[...nessus]
                  .sort((a, b) => Number(b.severity ?? 0) - Number(a.severity ?? 0))
                  .map((f, i) => {
                    const sc = nessusSevStyle(f.severity)
                    return (
                      <tr key={i}>
                        <td style={S.td}>
                          <span style={{
                            display: 'inline-block', padding: '2px 7px', borderRadius: 4,
                            fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.04em',
                            textTransform: 'uppercase', background: sc.bg, color: sc.text,
                            border: `1px solid ${sc.border}`,
                          }}>
                            {nessusSevLabel(f.severity)}
                          </span>
                        </td>
                        <td style={S.td}>{f.plugin_name || `Plugin ${f.plugin_id}`}</td>
                        <td style={{ ...S.td, ...S.monoTd }}>{f.port ? `${f.port}/${f.protocol || 'tcp'}` : '—'}</td>
                        <td style={{ ...S.td, color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                          {f.synopsis || f.description?.slice(0, 120) || '—'}
                        </td>
                      </tr>
                    )
                  })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}

// ── Main Hosts component ──────────────────────────────────────────────────────

export default function Hosts({ projectId }) {
  const [hosts,         setHosts]         = useState([])
  const [selectedIndex, setSelectedIndex] = useState(null)
  const [filter,        setFilter]        = useState('')
  const [loading,       setLoading]       = useState(true)
  const [lightboxUrl,   setLightboxUrl]   = useState(null)
  const [excludeTarget, setExcludeTarget] = useState(null)
  const [excluding,     setExcluding]     = useState(false)

  const fetchHosts = () => {
    if (!projectId) return
    api.projects.hosts(projectId)
      .then(data => {
        const list = Array.isArray(data) ? data : []
        setHosts(list)
        setLoading(false)
        setSelectedIndex(prev => {
          if (list.length === 0) return null
          if (prev != null && prev < list.length) return prev
          return list.length > 0 ? 0 : null
        })
      })
      .catch(() => setLoading(false))
  }

  useEffect(() => { fetchHosts() }, [projectId])
  useEffect(() => {
    if (!projectId) return
    const t = setInterval(fetchHosts, 5000)
    return () => clearInterval(t)
  }, [projectId])

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return hosts.map((h, i) => ({ h, i }))
    return hosts.map((h, i) => ({ h, i })).filter(({ h }) => (h.host || '').toLowerCase().includes(q))
  }, [hosts, filter])

  const current = selectedIndex != null ? hosts[selectedIndex] : null

  const doExclude = async () => {
    if (!excludeTarget) return
    setExcluding(true)
    try {
      await api.projects.excludeHost(projectId, excludeTarget)
      setExcludeTarget(null)
      setSelectedIndex(null)
      fetchHosts()
    } catch (e) {
      window.alert(e?.body?.detail || e?.message || 'Failed to exclude host')
    } finally {
      setExcluding(false)
    }
  }

  if (loading) return <div style={S.muted}>Loading hosts…</div>

  if (!hosts.length) {
    return (
      <div style={S.emptyState}>
        <p style={S.emptyTitle}>No hosts yet</p>
        <p style={S.muted}>Run Nmap and web scans to populate the host list.</p>
      </div>
    )
  }

  return (
    <div style={S.layout}>
      {/* Left: host list */}
      <aside style={S.sidebar}>
        <div style={S.sidebarHead}>
          <span style={S.sidebarLabel}>HOSTS</span>
          <span style={S.sidebarCount}>{hosts.length}</span>
        </div>
        <input
          type="search"
          placeholder="Filter by name…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={S.filterInput}
          aria-label="Filter hosts"
        />
        <ul style={S.hostList}>
          {filtered.length === 0
            ? <li style={S.muted}>No match.</li>
            : filtered.map(({ h, i }) => {
                const dot     = riskDot(h)
                const active  = selectedIndex === i
                const { ports, shots, nuclei, nessus } = hostSummary(h)
                return (
                  <li key={`${h.host}-${i}`}>
                    <button
                      type="button"
                      style={{ ...S.hostBtn, ...(active ? S.hostBtnActive : {}) }}
                      onClick={() => setSelectedIndex(i)}
                    >
                      <span style={S.hostBtnInner}>
                        <span style={S.hostName}>{h.host}</span>
                        <span style={S.hostMeta}>
                          {ports > 0  && <span>{ports}p</span>}
                          {shots > 0  && <span>{shots} 📷</span>}
                          {nuclei > 0 && <span style={{ color: '#fbbf24' }}>{nuclei} N</span>}
                          {nessus > 0 && <span style={{ color: '#f87171' }}>{nessus} Ns</span>}
                        </span>
                      </span>
                      <span style={{ ...S.riskDot, background: dot.color }} title={dot.label} />
                    </button>
                  </li>
                )
              })
          }
        </ul>
      </aside>

      {/* Right: detail */}
      <main style={S.main}>
        <HostDetail
          host={current}
          projectId={projectId}
          onExclude={setExcludeTarget}
          onScreenshotClick={setLightboxUrl}
        />
      </main>

      {/* Confirm exclude */}
      <ConfirmModal
        open={!!excludeTarget}
        title="Remove host from list?"
        message={excludeTarget ? `"${excludeTarget}" will be hidden from the Hosts tab. Re-run scans to restore it.` : ''}
        confirmLabel="Remove"
        cancelLabel="Cancel"
        danger
        loading={excluding}
        onConfirm={doExclude}
        onCancel={() => setExcludeTarget(null)}
      />

      {/* Lightbox */}
      {lightboxUrl && (
        <div style={S.lightboxOverlay} onClick={() => setLightboxUrl(null)}>
          <button type="button" style={S.lightboxClose} onClick={() => setLightboxUrl(null)}>×</button>
          <img src={lightboxUrl} alt="Screenshot" style={S.lightboxImg} onClick={e => e.stopPropagation()} />
        </div>
      )}
    </div>
  )
}

// ── Styles ────────────────────────────────────────────────────────────────────

const S = {
  layout: { display: 'grid', gridTemplateColumns: '260px 1fr', gap: 0, minHeight: 500, border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden', background: 'var(--surface)' },

  // Sidebar
  sidebar: { borderRight: '1px solid var(--border)', display: 'flex', flexDirection: 'column', minHeight: 0, background: 'var(--surface-muted)' },
  sidebarHead: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 14px 8px', borderBottom: '1px solid var(--border)' },
  sidebarLabel: { fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' },
  sidebarCount: { fontSize: '0.75rem', fontWeight: 600, padding: '1px 8px', background: 'var(--border)', borderRadius: 10, color: 'var(--text-muted)' },
  filterInput: { margin: '8px 10px', padding: '6px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', color: 'var(--text)', fontSize: '0.82rem' },
  hostList: { listStyle: 'none', margin: 0, padding: '4px 6px', overflowY: 'auto', flex: 1 },
  hostBtn: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, width: '100%', padding: '8px 10px', background: 'transparent', border: '1px solid transparent', borderRadius: 6, cursor: 'pointer', textAlign: 'left', marginBottom: 2, transition: 'all 0.1s' },
  hostBtnActive: { background: 'var(--accent-soft)', borderColor: 'var(--accent)' },
  hostBtnInner: { display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0, flex: 1 },
  hostName: { fontFamily: 'var(--font-mono)', fontSize: '0.82rem', fontWeight: 600, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  hostMeta: { display: 'flex', gap: 8, fontSize: '0.7rem', color: 'var(--text-muted)' },
  riskDot: { width: 8, height: 8, borderRadius: '50%', flexShrink: 0 },

  // Main panel
  main: { padding: 20, overflowY: 'auto', minHeight: 400 },
  selectHint: { color: 'var(--text-muted)', fontSize: '0.875rem', paddingTop: 40, textAlign: 'center' },

  // Host detail
  detailPanel: {},
  detailHeader: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 20 },
  detailHeaderLeft: { display: 'flex', alignItems: 'center', gap: 10 },
  detailHostname: { margin: 0, fontSize: '1.2rem', fontWeight: 700, fontFamily: 'var(--font-mono)' },
  detailHeaderActions: { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' },
  statPills: { display: 'flex', gap: 6, flexWrap: 'wrap' },
  statPill: { padding: '2px 9px', border: '1px solid var(--border)', borderRadius: 10, fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-muted)', background: 'var(--surface-muted)' },
  statPillWarn: { background: 'rgba(217,119,6,0.1)', borderColor: 'rgba(217,119,6,0.3)', color: '#fbbf24' },
  statPillDanger: { background: 'rgba(220,38,38,0.1)', borderColor: 'rgba(220,38,38,0.3)', color: '#f87171' },
  excludeBtn: { padding: '4px 10px', border: '1px solid rgba(220,38,38,0.35)', background: 'transparent', color: 'var(--danger)', borderRadius: 5, fontSize: '0.78rem', cursor: 'pointer' },

  // Sections
  section: { marginBottom: 24 },
  sectionTitle: { margin: '0 0 10px', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)' },

  // Tables
  tableWrap: { overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 7 },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' },
  th: { padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', background: 'var(--surface-muted)', borderBottom: '1px solid var(--border)' },
  td: { padding: '9px 12px', borderBottom: '1px solid var(--border)', color: 'var(--text)', verticalAlign: 'middle' },
  monoTd: { fontFamily: 'var(--font-mono)', fontSize: '0.8rem' },

  // Screenshots
  screenshotGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 },
  screenshotCard: { display: 'flex', flexDirection: 'column', gap: 4 },
  thumbBtn: { background: 'none', border: '1px solid var(--border)', borderRadius: 6, padding: 0, cursor: 'pointer', overflow: 'hidden' },
  thumbImg: { width: '100%', height: 110, objectFit: 'cover', display: 'block' },
  thumbCaption: { fontSize: '0.72rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },

  // Lightbox
  lightboxOverlay: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.88)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 24 },
  lightboxClose: { position: 'absolute', top: 16, right: 20, background: 'rgba(255,255,255,0.1)', border: 'none', color: '#fff', fontSize: '1.8rem', width: 40, height: 40, borderRadius: 8, cursor: 'pointer', lineHeight: 1 },
  lightboxImg: { maxWidth: '95vw', maxHeight: '92vh', objectFit: 'contain', borderRadius: 8 },

  // Empty / misc
  emptyState: { textAlign: 'center', padding: '48px 24px' },
  emptyTitle: { fontWeight: 600, fontSize: '1rem', margin: '0 0 8px' },
  muted: { color: 'var(--text-muted)', fontSize: '0.875rem', lineHeight: 1.5, margin: 0 },
}
