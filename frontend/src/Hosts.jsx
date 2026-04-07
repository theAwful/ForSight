import { useState, useEffect, useMemo } from 'react'
import { api } from './api'
import ConfirmModal from './ConfirmModal'

function exposureLevel(host) {
  const ports = (host?.ports && host.ports.length) || 0
  const findings = (host?.findings && host.findings.length) || 0
  const nessusFindings = (host?.nessus_findings && host.nessus_findings.length) || 0
  if (findings > 0 || nessusFindings > 0) return { level: 'high', color: 'var(--danger)', label: 'Findings' }
  if (ports >= 10) return { level: 'medium', color: 'var(--warn)', label: `${ports} ports` }
  if (ports > 0) return { level: 'low', color: 'var(--accent)', label: `${ports} ports` }
  return { level: 'minimal', color: 'var(--text-muted)', label: 'No ports' }
}

function findingLabel(f) {
  const name = f?.info?.name
  const template = f?.template
  if (name) return name
  if (template) return template.replace(/^[^/]+\//, '').replace(/[-_]/g, ' ')
  return 'Finding'
}

function findingSeverity(f) {
  const s = (f?.info?.severity || '').toLowerCase()
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s
  return null
}

function nessusSeverityStyle(sevIndex, label) {
  const keys = ['info', 'low', 'medium', 'high', 'critical']
  const k = Number.isFinite(sevIndex) && sevIndex >= 0 && sevIndex < keys.length ? keys[sevIndex] : String(label || '').toLowerCase()
  const map = {
    critical: styles.severity_critical,
    high: styles.severity_high,
    medium: styles.severity_medium,
    low: styles.severity_low,
    info: styles.severity_info,
    none: styles.severity_info,
  }
  return map[k] || styles.severity_info
}

/** Merge nmap port detail with by_port blocks so each open port is one row. */
function buildPortRows(host) {
  const byPort = host?.by_port && typeof host.by_port === 'object' ? host.by_port : {}
  const detailByPort = new Map()
  for (const p of host.ports_detail || []) {
    const n = Number(p.port)
    if (!Number.isNaN(n)) detailByPort.set(n, p)
  }
  const keys = Object.keys(byPort).sort((a, b) => (Number(a) || 0) - (Number(b) || 0))
  return keys.map((portKey) => {
    const portNum = Number(portKey)
    const detail = !Number.isNaN(portNum) ? detailByPort.get(portNum) : null
    const block = byPort[portKey] || { screenshots: [], findings: [] }
    return {
      portKey,
      portNum,
      detail,
      screenshots: block.screenshots || [],
      findings: block.findings || [],
    }
  })
}

function hostStats(host) {
  const portsCount = host?.ports_detail?.length || host?.ports?.length || 0
  const byPort = host?.by_port && typeof host.by_port === 'object' ? host.by_port : {}
  const shots = Object.values(byPort).reduce((n, b) => n + (b.screenshots?.length || 0), 0)
  const nuclei = Object.values(byPort).reduce((n, b) => n + (b.findings?.length || 0), 0)
  const nessus = host?.nessus_findings?.length || 0
  return { portsCount, shots, nuclei, nessus }
}

export default function Hosts({ projectId, onRefresh: _onRefresh }) {
  const [hosts, setHosts] = useState([])
  const [selectedIndex, setSelectedIndex] = useState(null)
  const [listFilter, setListFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [lightboxUrl, setLightboxUrl] = useState(null)
  const [excludeConfirm, setExcludeConfirm] = useState(null)
  const [excluding, setExcluding] = useState(false)

  const fetchHosts = () => {
    if (!projectId) return
    api.projects
      .hosts(projectId)
      .then((data) => {
        const list = Array.isArray(data) ? data : []
        setHosts(list)
        setLoading(false)
        setSelectedIndex((prev) => {
          if (list.length === 0) return null
          if (prev != null && prev < list.length) return prev
          return 0
        })
      })
      .catch(() => setLoading(false))
  }

  useEffect(() => {
    fetchHosts()
  }, [projectId])

  useEffect(() => {
    if (!projectId) return
    const t = setInterval(fetchHosts, 3000)
    return () => clearInterval(t)
  }, [projectId])

  const filteredHosts = useMemo(() => {
    const q = listFilter.trim().toLowerCase()
    if (!q) return hosts.map((h, i) => ({ host: h, index: i }))
    return hosts
      .map((h, i) => ({ host: h, index: i }))
      .filter(({ host: h }) => (h.host || '').toLowerCase().includes(q))
  }, [hosts, listFilter])

  const current = selectedIndex != null ? hosts[selectedIndex] : null

  const confirmExclude = async () => {
    if (!excludeConfirm || !projectId) return
    const hostToExclude = excludeConfirm
    setExcludeConfirm(null)
    setExcluding(true)
    try {
      await api.projects.excludeHost(projectId, hostToExclude)
      setSelectedIndex(null)
      fetchHosts()
    } catch (err) {
      window.alert(err?.body?.detail || err?.message || 'Failed to remove host')
    } finally {
      setExcluding(false)
    }
  }

  if (loading) return <div style={styles.msg}>Loading hosts…</div>
  if (!hosts.length) {
    return (
      <div className="hosts-empty" style={styles.emptyState}>
        <p style={styles.emptyTitle}>No hosts yet</p>
        <p style={styles.emptyText}>Run Nmap and web scans (e.g. Gowitness, Nuclei) to see targets here. Each host groups open ports with screenshots and findings on the same row.</p>
      </div>
    )
  }

  return (
    <div className="hosts-layout" style={styles.layout}>
      <aside className="hosts-sidebar" style={styles.sidebar}>
        <div style={styles.sidebarHead}>
          <h2 style={styles.sidebarTitle}>Hosts</h2>
          <span style={styles.sidebarCount}>{hosts.length}</span>
        </div>
        <input
          type="search"
          className="input-search hosts-search"
          placeholder="Filter by name…"
          value={listFilter}
          onChange={(e) => setListFilter(e.target.value)}
          style={styles.searchInput}
          aria-label="Filter hosts"
        />
        <ul style={styles.hostList} className="hosts-list">
          {filteredHosts.length === 0 ? (
            <li style={styles.filterEmpty}>No hosts match.</li>
          ) : (
            filteredHosts.map(({ host: h, index: i }) => {
              const exp = exposureLevel(h)
              const isActive = selectedIndex === i
              const { portsCount, shots, nuclei, nessus } = hostStats(h)
              return (
                <li key={`${h.host}-${i}`} style={styles.hostLi}>
                  <button
                    type="button"
                    style={{
                      ...styles.hostBtn,
                      ...(isActive ? styles.hostBtnActive : {}),
                    }}
                    onClick={() => setSelectedIndex(i)}
                  >
                    <span style={styles.hostBtnMain}>
                      <span style={styles.hostName}>{h.host}</span>
                      <span style={styles.hostMeta}>
                        {portsCount > 0 && <span>{portsCount} ports</span>}
                        {(shots > 0 || nuclei > 0 || nessus > 0) && (
                          <span style={styles.hostMetaEvidence}>
                            {[
                              shots > 0 && `${shots} screenshot${shots !== 1 ? 's' : ''}`,
                              nuclei > 0 && `${nuclei} Nuclei`,
                              nessus > 0 && `${nessus} Nessus`,
                            ]
                              .filter(Boolean)
                              .join(' · ')}
                          </span>
                        )}
                      </span>
                    </span>
                    <span
                      style={{
                        ...styles.signalDot,
                        background: exp.color,
                        ...(exp.level === 'minimal' ? { opacity: 0.5 } : {}),
                      }}
                      title={exp.label}
                      aria-hidden
                    />
                  </button>
                </li>
              )
            })
          )}
        </ul>
      </aside>

      <article className="hosts-main" style={styles.main}>
        {current ? (
          <>
            <header style={styles.detailHeader}>
              <div style={styles.detailTitleBlock}>
                <h1 style={styles.detailTitle}>{current.host}</h1>
                <div style={styles.chipRow}>
                  {(() => {
                    const { portsCount, shots, nuclei, nessus } = hostStats(current)
                    const chips = [
                      portsCount > 0 && { k: 'ports', label: `${portsCount} open ports` },
                      shots > 0 && { k: 'shots', label: `${shots} screenshots` },
                      nuclei > 0 && { k: 'nuclei', label: `${nuclei} Nuclei` },
                      nessus > 0 && { k: 'nessus', label: `${nessus} Nessus` },
                    ].filter(Boolean)
                    if (!chips.length) {
                      return <span style={styles.chipMuted}>No scan evidence yet</span>
                    }
                    return chips.map((c) => (
                      <span key={c.k} style={styles.statChip}>
                        {c.label}
                      </span>
                    ))
                  })()}
                </div>
              </div>
              <div style={styles.detailActions}>
                {(() => {
                  const exp = exposureLevel(current)
                  return (
                    <span style={{ ...styles.badgePill, background: exp.color, color: exp.level === 'minimal' ? 'var(--text)' : 'var(--accent-text)' }}>
                      {exp.label}
                    </span>
                  )
                })()}
                <button
                  type="button"
                  className="btn-secondary"
                  style={styles.removeHostBtn}
                  onClick={() => setExcludeConfirm(current.host)}
                  title="Remove this host from the list (e.g. out-of-scope)"
                >
                  Remove from list
                </button>
              </div>
            </header>

            {current.insights?.length > 0 && (
              <div style={styles.insightsBanner}>
                <span style={styles.insightsLabel}>Scanner notes</span>
                <ul style={styles.insightsList}>
                  {current.insights.map((line, i) => (
                    <li key={i} style={styles.insightItem}>{line}</li>
                  ))}
                </ul>
              </div>
            )}

            {(() => {
              const portRows = buildPortRows(current)
              const nessusList = current.nessus_findings || []

              if (!portRows.length && !nessusList.length) {
                return <p style={styles.mutedLine}>No ports, screenshots, or findings for this host yet.</p>
              }

              if (!portRows.length && nessusList.length > 0) {
                return <NessusSection findings={nessusList} />
              }

              return (
                <div style={styles.portStack}>
                  {portRows.map((row) => (
                    <PortServiceCard
                      key={row.portKey}
                      projectId={projectId}
                      row={row}
                      onScreenshotClick={setLightboxUrl}
                    />
                  ))}
                  {nessusList.length > 0 && <NessusSection findings={nessusList} />}
                </div>
              )
            })()}
          </>
        ) : (
          <p style={styles.mutedLine}>Select a host from the list.</p>
        )}
      </article>

      <ConfirmModal
        open={!!excludeConfirm}
        title="Remove host from list?"
        message={
          excludeConfirm
            ? `"${excludeConfirm}" will be hidden from the Hosts tab (e.g. out-of-scope). You can re-add by re-running scans.`
            : ''
        }
        confirmLabel="Remove"
        cancelLabel="Cancel"
        danger
        loading={excluding}
        onConfirm={confirmExclude}
        onCancel={() => setExcludeConfirm(null)}
      />
      {lightboxUrl && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Screenshot full size"
          style={styles.lightboxOverlay}
          onClick={() => setLightboxUrl(null)}
        >
          <button
            type="button"
            style={styles.lightboxClose}
            onClick={() => setLightboxUrl(null)}
            aria-label="Close"
          >
            ×
          </button>
          <img src={lightboxUrl} alt="Screenshot" style={styles.lightboxImg} onClick={(e) => e.stopPropagation()} />
        </div>
      )}
    </div>
  )
}

function PortServiceCard({ projectId, row, onScreenshotClick }) {
  const { portKey, portNum, detail, screenshots, findings } = row
  const isOther = portKey === '0' || Number.isNaN(portNum)
  const portLabel = isOther ? 'Unmatched URL / other' : `Port ${portKey}`
  const serviceLine = detail
    ? [detail.service, [detail.product, detail.version].filter(Boolean).join(' ')].filter(Boolean).join(' · ') || '—'
    : null
  const hasWebEvidence = screenshots.length > 0 || findings.length > 0

  return (
    <section style={styles.portCard} className="hosts-port-card">
      <div style={styles.portCardHead}>
        <div style={styles.portCardHeadText}>
          <span style={styles.portCardTitle}>{portLabel}</span>
          {serviceLine && <span style={styles.portCardService}>{serviceLine}</span>}
          {!detail && !isOther && <span style={styles.portCardServiceMuted}>No Nmap service detail</span>}
        </div>
        {(screenshots.length > 0 || findings.length > 0) && (
          <div style={styles.portCardBadges}>
            {screenshots.length > 0 && <span style={styles.miniBadge}>{screenshots.length} shot{screenshots.length !== 1 ? 's' : ''}</span>}
            {findings.length > 0 && <span style={styles.miniBadgeWarn}>{findings.length} Nuclei</span>}
          </div>
        )}
      </div>

      {hasWebEvidence && (
        <div style={styles.portCardBody} className="hosts-port-card-body">
          {screenshots.length > 0 && (
            <div style={styles.evidenceCol}>
              <span style={styles.evidenceColLabel}>Screenshots</span>
              <div style={styles.thumbRow}>
                {screenshots.map((s, i) => {
                  const imgUrl = s.filename ? api.screenshots.url(projectId, s.filename) : ''
                  return (
                    <div key={i} style={styles.thumbWrap}>
                      <button
                        type="button"
                        style={styles.thumbBtn}
                        onClick={() => imgUrl && onScreenshotClick(imgUrl)}
                        title="Enlarge"
                      >
                        <img src={imgUrl} alt="" style={styles.thumbImg} />
                      </button>
                      <span style={styles.thumbCaption} title={s.url || s.filename}>
                        {s.url || s.filename || 'Screenshot'}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
          {findings.length > 0 && (
            <div style={styles.evidenceCol}>
              <span style={styles.evidenceColLabel}>Nuclei</span>
              <ul style={styles.findingList}>
                {findings.map((f, i) => {
                  const sev = findingSeverity(f)
                  return (
                    <li key={i} style={styles.findingRow}>
                      <span style={styles.findingRowTitle}>{findingLabel(f)}</span>
                      {sev && (
                        <span style={{ ...styles.findingPill, ...styles[`severity_${sev}`] }}>{sev}</span>
                      )}
                      {f?.template && <code style={styles.findingTpl}>{f.template}</code>}
                    </li>
                  )
                })}
              </ul>
            </div>
          )}
        </div>
      )}

      {isOther && hasWebEvidence && (
        <p style={styles.portCardHint}>Port could not be inferred from the URL; evidence is grouped here.</p>
      )}
    </section>
  )
}

function NessusSection({ findings }) {
  return (
    <section style={styles.nessusSection}>
      <h3 style={styles.nessusHeading}>Nessus</h3>
      <p style={styles.nessusLead}>Scanner findings for this host (not tied to a single service row).</p>
      <ul style={styles.nessusList}>
        {findings.map((f, i) => {
          const sevIdx = Number(f.severity)
          const sevName = Number.isFinite(sevIdx) && sevIdx >= 0 && sevIdx <= 4
            ? ['None', 'Low', 'Medium', 'High', 'Critical'][sevIdx]
            : String(f.severity ?? '')
          return (
            <li key={i} style={styles.nessusCard}>
              <div style={styles.nessusCardTop}>
                <span style={styles.nessusCardTitle}>{f.plugin_name || f.plugin_id || 'Finding'}</span>
                {f.severity != null && (
                  <span style={{ ...styles.findingPill, ...nessusSeverityStyle(sevIdx, sevName) }}>{sevName}</span>
                )}
              </div>
              {(f.port || f.protocol) && (
                <div style={styles.nessusMeta}>
                  {f.port ? `${f.port}/${f.protocol || 'tcp'}` : f.protocol}
                </div>
              )}
              {f.synopsis && <p style={styles.nessusSynopsis}>{f.synopsis}</p>}
            </li>
          )
        })}
      </ul>
    </section>
  )
}

const styles = {
  msg: { color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' },
  layout: {
    minHeight: 420,
    fontFamily: 'var(--font-sans)',
    fontSize: '0.875rem',
  },
  sidebar: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: '1rem',
    boxShadow: 'var(--shadow-sm)',
    position: 'sticky',
    top: '0.75rem',
    maxHeight: 'min(85vh, 720px)',
    display: 'flex',
    flexDirection: 'column',
    minHeight: 0,
  },
  sidebarHead: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.65rem',
  },
  sidebarTitle: {
    margin: 0,
    fontSize: '0.6875rem',
    fontWeight: 600,
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
  },
  sidebarCount: {
    fontSize: '0.75rem',
    fontWeight: 600,
    color: 'var(--text-muted)',
    background: 'var(--surface-muted)',
    padding: '0.15rem 0.45rem',
    borderRadius: 'var(--radius-sm)',
  },
  searchInput: {
    width: '100%',
    marginBottom: '0.75rem',
    padding: '0.45rem 0.65rem',
    fontSize: '0.8125rem',
  },
  hostList: {
    listStyle: 'none',
    margin: 0,
    padding: 0,
    overflowY: 'auto',
    flex: 1,
    minHeight: 0,
  },
  filterEmpty: {
    padding: '0.75rem',
    color: 'var(--text-muted)',
    fontSize: '0.8125rem',
  },
  hostLi: { marginBottom: '0.25rem' },
  hostBtn: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '0.5rem',
    width: '100%',
    padding: '0.55rem 0.65rem',
    background: 'transparent',
    color: 'var(--text)',
    border: '1px solid transparent',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.8125rem',
    textAlign: 'left',
    transition: 'background-color 0.15s ease, border-color 0.15s ease',
  },
  hostBtnActive: {
    background: 'var(--accent-soft)',
    borderColor: 'var(--accent)',
    color: 'var(--text)',
  },
  hostBtnMain: { minWidth: 0, flex: 1 },
  hostName: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8125rem',
    fontWeight: 500,
    display: 'block',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  hostMeta: {
    display: 'block',
    marginTop: '0.2rem',
    fontSize: '0.6875rem',
    color: 'var(--text-muted)',
    lineHeight: 1.35,
  },
  hostMetaEvidence: { display: 'block', opacity: 0.9 },
  signalDot: {
    width: 8,
    height: 8,
    borderRadius: '50%',
    flexShrink: 0,
    marginTop: '0.35rem',
  },
  main: {
    minWidth: 0,
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: '1.25rem 1.35rem',
    boxShadow: 'var(--shadow-sm)',
  },
  detailHeader: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '1rem',
    flexWrap: 'wrap',
    marginBottom: '1.15rem',
    paddingBottom: '1rem',
    borderBottom: '1px solid var(--border)',
  },
  detailTitleBlock: { minWidth: 0, flex: '1 1 200px' },
  detailTitle: {
    margin: '0 0 0.5rem 0',
    fontSize: '1.2rem',
    fontWeight: 600,
    fontFamily: 'var(--font-mono)',
    letterSpacing: '-0.02em',
    wordBreak: 'break-all',
  },
  chipRow: { display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center' },
  statChip: {
    fontSize: '0.72rem',
    fontWeight: 500,
    color: 'var(--text-muted)',
    background: 'var(--surface-muted)',
    border: '1px solid var(--border-light)',
    padding: '0.2rem 0.5rem',
    borderRadius: 'var(--radius-sm)',
  },
  chipMuted: { fontSize: '0.8rem', color: 'var(--text-muted)' },
  detailActions: { display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0, flexWrap: 'wrap' },
  badgePill: {
    fontSize: '0.6875rem',
    fontWeight: 600,
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    padding: '0.25rem 0.55rem',
    borderRadius: 'var(--radius-sm)',
  },
  removeHostBtn: {
    fontSize: '0.8125rem',
    color: 'var(--danger)',
    borderColor: 'var(--danger)',
  },
  insightsBanner: {
    marginBottom: '1.25rem',
    padding: '0.75rem 1rem',
    background: 'var(--surface-muted)',
    border: '1px solid var(--border-light)',
    borderRadius: 'var(--radius)',
  },
  insightsLabel: {
    display: 'block',
    fontSize: '0.65rem',
    fontWeight: 600,
    letterSpacing: '0.07em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
    marginBottom: '0.35rem',
  },
  insightsList: { listStyle: 'none', margin: 0, padding: 0 },
  insightItem: {
    fontSize: '0.8125rem',
    color: 'var(--text-muted)',
    padding: '0.25rem 0',
    borderBottom: '1px solid var(--border-light)',
  },
  mutedLine: { margin: 0, color: 'var(--text-muted)', fontSize: '0.875rem' },
  portStack: { display: 'flex', flexDirection: 'column', gap: '1rem' },
  portCard: {
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    overflow: 'hidden',
    background: 'var(--bg-elevated)',
  },
  portCardHead: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '0.75rem',
    flexWrap: 'wrap',
    padding: '0.85rem 1rem',
    background: 'var(--surface-muted)',
    borderBottom: '1px solid var(--border-light)',
  },
  portCardHeadText: { minWidth: 0, flex: '1 1 160px' },
  portCardTitle: {
    display: 'block',
    fontFamily: 'var(--font-mono)',
    fontWeight: 600,
    fontSize: '0.95rem',
    color: 'var(--text)',
  },
  portCardService: {
    display: 'block',
    marginTop: '0.25rem',
    fontSize: '0.8125rem',
    color: 'var(--text-muted)',
  },
  portCardServiceMuted: {
    display: 'block',
    marginTop: '0.25rem',
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
    fontStyle: 'italic',
  },
  portCardBadges: { display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center' },
  miniBadge: {
    fontSize: '0.65rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    padding: '0.15rem 0.45rem',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--accent-soft)',
    color: 'var(--accent)',
  },
  miniBadgeWarn: {
    fontSize: '0.65rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    padding: '0.15rem 0.45rem',
    borderRadius: 'var(--radius-sm)',
    background: 'rgba(217, 119, 6, 0.15)',
    color: 'var(--warn)',
  },
  portCardHint: {
    margin: 0,
    padding: '0 1rem 0.85rem',
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
  },
  portCardBody: {
    display: 'grid',
    gap: '1rem',
    padding: '1rem',
  },
  evidenceCol: { minWidth: 0 },
  evidenceColLabel: {
    display: 'block',
    fontSize: '0.65rem',
    fontWeight: 600,
    letterSpacing: '0.07em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
    marginBottom: '0.5rem',
  },
  thumbRow: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '0.65rem',
  },
  thumbWrap: { width: 'min(140px, 100%)' },
  thumbBtn: {
    padding: 0,
    border: 'none',
    background: 'none',
    cursor: 'pointer',
    borderRadius: 'var(--radius-sm)',
    overflow: 'hidden',
    display: 'block',
    width: '100%',
  },
  thumbImg: {
    width: '100%',
    height: 88,
    objectFit: 'cover',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    display: 'block',
  },
  thumbCaption: {
    display: 'block',
    marginTop: '0.25rem',
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  findingList: { listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: '0.5rem' },
  findingRow: {
    padding: '0.5rem 0.65rem',
    background: 'var(--surface)',
    border: '1px solid var(--border-light)',
    borderRadius: 'var(--radius-sm)',
    display: 'flex',
    flexWrap: 'wrap',
    alignItems: 'baseline',
    gap: '0.35rem 0.5rem',
  },
  findingRowTitle: { fontWeight: 600, fontSize: '0.8125rem', color: 'var(--text)', flex: '1 1 140px', minWidth: 0 },
  findingPill: {
    fontSize: '0.6rem',
    fontWeight: 600,
    letterSpacing: '0.05em',
    textTransform: 'uppercase',
    padding: '0.15rem 0.4rem',
    borderRadius: 'var(--radius-sm)',
  },
  findingTpl: {
    flexBasis: '100%',
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    display: 'block',
  },
  severity_critical: { background: 'var(--danger)', color: '#fff' },
  severity_high: { background: 'var(--danger)', color: '#fff' },
  severity_medium: { background: 'var(--warn)', color: '#fff' },
  severity_low: { background: 'var(--accent)', color: 'var(--accent-text)' },
  severity_info: { background: 'var(--border)', color: 'var(--text-muted)' },
  nessusSection: {
    marginTop: '0.25rem',
    paddingTop: '1.25rem',
    borderTop: '1px dashed var(--border)',
  },
  nessusHeading: {
    margin: '0 0 0.35rem 0',
    fontSize: '0.75rem',
    fontWeight: 600,
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
  },
  nessusLead: { margin: '0 0 0.85rem 0', fontSize: '0.8125rem', color: 'var(--text-muted)', lineHeight: 1.45 },
  nessusList: { listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: '0.65rem' },
  nessusCard: {
    padding: '0.85rem 1rem',
    background: 'var(--surface-muted)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
  },
  nessusCardTop: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '0.5rem',
    flexWrap: 'wrap',
  },
  nessusCardTitle: { fontWeight: 600, fontSize: '0.875rem', color: 'var(--text)', flex: '1 1 200px' },
  nessusMeta: {
    marginTop: '0.35rem',
    fontSize: '0.75rem',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
  },
  nessusSynopsis: {
    margin: '0.5rem 0 0 0',
    fontSize: '0.8125rem',
    color: 'var(--text-muted)',
    lineHeight: 1.45,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
  },
  emptyState: { maxWidth: 520, padding: '1rem 0' },
  emptyTitle: { margin: '0 0 0.5rem 0', fontSize: '1.05rem', fontWeight: 600, color: 'var(--text)' },
  emptyText: { margin: 0, color: 'var(--text-muted)', lineHeight: 1.55, fontSize: '0.9rem' },
  lightboxOverlay: {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0,0,0,0.85)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
    padding: '2rem',
  },
  lightboxClose: {
    position: 'absolute',
    top: '1rem',
    right: '1rem',
    width: 40,
    height: 40,
    borderRadius: '50%',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text)',
    fontSize: '1.5rem',
    lineHeight: 1,
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  lightboxImg: {
    maxWidth: '95%',
    maxHeight: '95%',
    objectFit: 'contain',
    borderRadius: 'var(--radius)',
  },
}
