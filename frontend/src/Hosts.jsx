import { useState, useEffect } from 'react'
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

export default function Hosts({ projectId, onRefresh }) {
  const [hosts, setHosts] = useState([])
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [lightboxUrl, setLightboxUrl] = useState(null)
  const [excludeConfirm, setExcludeConfirm] = useState(null)
  const [excluding, setExcluding] = useState(false)

  const fetchHosts = () => {
    if (!projectId) return
    api.projects.hosts(projectId).then((data) => {
      setHosts(Array.isArray(data) ? data : [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }

  useEffect(() => {
    fetchHosts()
  }, [projectId])

  useEffect(() => {
    if (!projectId) return
    const t = setInterval(fetchHosts, 3000)
    return () => clearInterval(t)
  }, [projectId])

  const confirmExclude = async () => {
    if (!excludeConfirm || !projectId) return
    const hostToExclude = excludeConfirm
    setExcludeConfirm(null)
    setExcluding(true)
    try {
      await api.projects.excludeHost(projectId, hostToExclude)
      setSelected(null)
      fetchHosts()
    } catch (err) {
      window.alert(err?.body?.detail || err?.message || 'Failed to remove host')
    } finally {
      setExcluding(false)
    }
  }

  if (loading) return <div style={styles.msg}>Loading hosts…</div>
  if (!hosts.length) return <div style={styles.msg}>No hosts yet. Run nmap and web host scans to populate.</div>

  const current = selected != null ? hosts[selected] : null

  return (
    <div style={styles.wrapper} className="hosts-view">
      <aside style={styles.sidebar}>
        <h2 style={styles.sidebarTitle}>Hosts</h2>
        <ul style={styles.hostList}>
          {hosts.map((h, i) => {
            const exp = exposureLevel(h)
            const isActive = selected === i
            return (
              <li key={h.host} style={styles.hostLi}>
                <button
                  type="button"
                  style={{
                    ...styles.hostBtn,
                    ...(isActive ? styles.hostBtnActive : {}),
                  }}
                  onClick={() => setSelected(i)}
                >
                  <span style={styles.hostName}>{h.host}</span>
                  <span
                    style={{
                      ...styles.badge,
                      background: exp.color,
                      color: exp.level === 'minimal' ? 'var(--text)' : 'var(--accent-text)',
                    }}
                    title={exp.label}
                  >
                    {exp.label}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      </aside>
      <article style={styles.detail}>
        {current ? (
          <>
            <header style={styles.detailHeader}>
              <div style={styles.detailTitleRow}>
                <h1 style={styles.detailTitle}>{current.host}</h1>
                {(() => {
                  const exp = exposureLevel(current)
                  return (
                    <span style={{ ...styles.badge, ...styles.badgePill, background: exp.color }}>
                      {exp.label}
                    </span>
                  )
                })()}
              </div>
              <button
                type="button"
                className="btn-secondary"
                style={styles.removeHostBtn}
                onClick={() => setExcludeConfirm(current.host)}
                title="Remove this host from the list (e.g. out-of-scope)"
              >
                Remove from list
              </button>
            </header>
            {current.insights?.length > 0 && (
              <section style={styles.block}>
                <h3 style={styles.blockTitle}>Insights</h3>
                <ul style={styles.insightsList}>
                  {current.insights.map((line, i) => (
                    <li key={i} style={styles.insightItem}>{line}</li>
                  ))}
                </ul>
              </section>
            )}
            {(current.ports_detail?.length > 0 || current.ports?.length > 0) && (
              <section style={styles.block}>
                <h3 style={styles.blockTitle}>
                  Ports <span style={styles.blockCount}>{current.ports_detail?.length || current.ports?.length || 0}</span>
                </h3>
                {current.ports_detail?.length > 0 ? (
                  <div style={styles.portTable}>
                    {current.ports_detail.map((p, i) => (
                      <div
                        key={i}
                        style={{
                          ...styles.portRow,
                          ...(i === current.ports_detail.length - 1 ? { borderBottom: 'none' } : {}),
                        }}
                      >
                        <span style={styles.portNum}>{p.port}</span>
                        <span style={styles.portService}>{p.service || '—'}</span>
                        <span style={styles.portProduct}>
                          {[p.product, p.version].filter(Boolean).join(' ') || '—'}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={styles.portList}>{current.ports?.join(', ')}</p>
                )}
              </section>
            )}
            {current.by_port && Object.keys(current.by_port).length > 0 ? (
              Object.entries(current.by_port)
                .filter(([portKey]) => {
                  const block = current.by_port[portKey]
                  return (block.screenshots?.length > 0 || block.findings?.length > 0)
                })
                .sort(([a], [b]) => {
                  const na = Number(a) || 0
                  const nb = Number(b) || 0
                  if (na === 0) return 1
                  if (nb === 0) return -1
                  return na - nb
                })
                .map(([portKey, block]) => {
                  const portLabel = portKey === '0' ? 'Other' : `Port ${portKey}`
                  return (
                    <section key={portKey} style={styles.block}>
                      <h3 style={styles.blockTitle}>{portLabel}</h3>
                      {block.screenshots?.length > 0 && (
                        <div style={styles.screenshotGrid}>
                          {block.screenshots.map((s, i) => {
                            const imgUrl = s.filename ? api.screenshots.url(projectId, s.filename) : ''
                            return (
                              <div key={i} style={styles.screenshotCard}>
                                <button
                                  type="button"
                                  style={styles.screenshotBtn}
                                  onClick={() => imgUrl && setLightboxUrl(imgUrl)}
                                  title="Click to enlarge"
                                >
                                  <img
                                    src={imgUrl}
                                    alt={s.url || s.filename || 'Screenshot'}
                                    style={styles.screenshotImg}
                                  />
                                </button>
                                <span style={styles.screenshotUrl}>{s.url || s.filename || 'Screenshot'}</span>
                              </div>
                            )
                          })}
                        </div>
                      )}
                      {block.findings?.length > 0 && (
                        <div style={styles.findingsBlock}>
                          <h4 style={styles.findingsSubtitle}>Nuclei findings</h4>
                          {block.findings.map((f, i) => (
                            <div key={i} style={styles.findingCard}>
                              <div style={styles.findingCardHeader}>
                                <span style={styles.findingTitle}>{findingLabel(f)}</span>
                                {findingSeverity(f) && (
                                  <span
                                    style={{
                                      ...styles.findingSeverity,
                                      ...styles[`severity_${findingSeverity(f)}`],
                                    }}
                                  >
                                    {findingSeverity(f)}
                                  </span>
                                )}
                              </div>
                              {f?.template && (
                                <div style={styles.findingTemplate} title={f.template}>
                                  {f.template}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </section>
                  )
                })
            ) : (
              <>
                {current.screenshots?.length > 0 && (
                  <section style={styles.block}>
                    <h3 style={styles.blockTitle}>Screenshots</h3>
                    <div style={styles.screenshotGrid}>
                      {current.screenshots.map((s, i) => {
                        const imgUrl = s.filename ? api.screenshots.url(projectId, s.filename) : ''
                        return (
                          <div key={i} style={styles.screenshotCard}>
                            <button
                              type="button"
                              style={styles.screenshotBtn}
                              onClick={() => imgUrl && setLightboxUrl(imgUrl)}
                              title="Click to enlarge"
                            >
                              <img src={imgUrl} alt={s.url || s.filename || 'Screenshot'} style={styles.screenshotImg} />
                            </button>
                            <span style={styles.screenshotUrl}>{s.url || s.filename || 'Screenshot'}</span>
                          </div>
                        )
                      })}
                    </div>
                  </section>
                )}
                {current.findings?.length > 0 && (
                  <section style={styles.block}>
                    <h3 style={styles.blockTitle}>
                      Findings <span style={styles.blockCount}>{current.findings.length}</span>
                    </h3>
                    <div style={styles.findingsBlock}>
                      <h4 style={styles.findingsSubtitle}>Nuclei findings</h4>
                      {current.findings.map((f, i) => (
                        <div key={i} style={styles.findingCard}>
                          <div style={styles.findingCardHeader}>
                            <span style={styles.findingTitle}>{findingLabel(f)}</span>
                            {findingSeverity(f) && (
                              <span
                                style={{
                                  ...styles.findingSeverity,
                                  ...styles[`severity_${findingSeverity(f)}`],
                                }}
                              >
                                {findingSeverity(f)}
                              </span>
                            )}
                          </div>
                          {f?.template && (
                            <div style={styles.findingTemplate} title={f.template}>
                              {f.template}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </section>
                )}
                {current.nessus_findings?.length > 0 && (
                  <section style={styles.block}>
                    <h3 style={styles.blockTitle}>
                      Nessus <span style={styles.blockCount}>{current.nessus_findings.length}</span>
                    </h3>
                    <div style={styles.findingsBlock}>
                      <h4 style={styles.findingsSubtitle}>Nessus findings</h4>
                      {current.nessus_findings.map((f, i) => (
                        <div key={i} style={styles.findingCard}>
                          <div style={styles.findingCardHeader}>
                            <span style={styles.findingTitle}>{f.plugin_name || f.plugin_id || 'Nessus finding'}</span>
                            {f.severity != null && (
                              <span
                                style={{
                                  ...styles.findingSeverity,
                                  ...styles[`severity_${['info', 'low', 'medium', 'high', 'critical'][Number(f.severity)] || String(f.severity).toLowerCase()}`],
                                }}
                              >
                                {['None', 'Low', 'Medium', 'High', 'Critical'][Number(f.severity)] ?? f.severity}
                              </span>
                            )}
                          </div>
                          {(f.port || f.protocol) && (
                            <div style={styles.findingTemplate}>
                              {f.port ? `${f.port}/${f.protocol || 'tcp'}` : f.protocol}
                            </div>
                          )}
                          {f.synopsis && (
                            <div style={styles.findingSynopsis}>{f.synopsis}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  </section>
                )}
              </>
            )}
            {!current.ports?.length && !current.screenshots?.length && !current.findings?.length && !current.nessus_findings?.length && (
              <p style={styles.empty}>No ports, screenshots, or findings for this host yet.</p>
            )}
          </>
        ) : (
          <p style={styles.empty}>Select a host from the list.</p>
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
          <img
            src={lightboxUrl}
            alt="Screenshot"
            style={styles.lightboxImg}
            onClick={(e) => e.stopPropagation()}
          />
        </div>
      )}
    </div>
  )
}

const styles = {
  wrapper: {
    display: 'flex',
    gap: '1.5rem',
    minHeight: 420,
    fontFamily: 'var(--font-sans)',
    fontSize: '0.875rem',
  },
  msg: { color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' },
  sidebar: {
    flexShrink: 0,
    width: 280,
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: '1rem',
    boxShadow: 'var(--shadow-sm)',
  },
  sidebarTitle: {
    margin: '0 0 0.75rem 0',
    fontSize: '0.6875rem',
    fontWeight: 600,
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
  },
  hostList: { listStyle: 'none', margin: 0, padding: 0 },
  hostLi: { marginBottom: '0.125rem' },
  hostBtn: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '0.5rem',
    width: '100%',
    padding: '0.5rem 0.75rem',
    background: 'transparent',
    color: 'var(--text)',
    border: 'none',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.875rem',
    textAlign: 'left',
    transition: 'background-color 0.15s ease',
  },
  hostBtnActive: {
    background: 'var(--accent)',
    color: 'var(--accent-text)',
  },
  hostName: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8125rem',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  badge: {
    flexShrink: 0,
    fontSize: '0.6875rem',
    fontWeight: 600,
    letterSpacing: '0.02em',
    padding: '0.2rem 0.45rem',
    borderRadius: 'var(--radius-sm)',
  },
  badgePill: { color: 'var(--accent-text)' },
  detail: {
    flex: 1,
    minWidth: 0,
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: '1.25rem',
    boxShadow: 'var(--shadow-sm)',
  },
  detailHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '0.75rem',
    flexWrap: 'wrap',
    marginBottom: '1.25rem',
    paddingBottom: '1rem',
    borderBottom: '1px solid var(--border)',
  },
  detailTitleRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    flexWrap: 'wrap',
  },
  detailTitle: {
    margin: 0,
    fontSize: '1.125rem',
    fontWeight: 600,
    fontFamily: 'var(--font-mono)',
    letterSpacing: '-0.01em',
  },
  removeHostBtn: {
    fontSize: '0.8125rem',
    color: 'var(--danger)',
    borderColor: 'var(--danger)',
  },
  block: {
    marginBottom: '1.5rem',
  },
  blockTitle: {
    margin: '0 0 0.5rem 0',
    fontSize: '0.6875rem',
    fontWeight: 600,
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
  },
  blockCount: {
    fontWeight: 500,
    letterSpacing: '0',
    textTransform: 'none',
    color: 'var(--text)',
  },
  portTable: {
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    overflow: 'hidden',
  },
  portRow: {
    display: 'grid',
    gridTemplateColumns: '4rem 6rem 1fr',
    gap: '1rem',
    padding: '0.5rem 0.75rem',
    borderBottom: '1px solid var(--border)',
    fontFamily: 'var(--font-sans)',
    fontSize: '0.8125rem',
  },
  portNum: {
    fontFamily: 'var(--font-mono)',
    fontWeight: 600,
    color: 'var(--text)',
  },
  portService: {
    fontFamily: 'var(--font-mono)',
    color: 'var(--accent)',
  },
  portProduct: {
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  portList: {
    margin: 0,
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8125rem',
    color: 'var(--text-muted)',
  },
  insightsList: { listStyle: 'none', margin: 0, padding: 0 },
  insightItem: {
    padding: '0.375rem 0',
    borderBottom: '1px solid var(--border-light)',
    fontSize: '0.8125rem',
    color: 'var(--text-muted)',
  },
  screenshotGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
    gap: '0.75rem',
  },
  screenshotCard: { display: 'flex', flexDirection: 'column', gap: '0.25rem' },
  screenshotBtn: {
    padding: 0,
    border: 'none',
    background: 'none',
    cursor: 'pointer',
    borderRadius: 'var(--radius-sm)',
    overflow: 'hidden',
    display: 'block',
  },
  screenshotImg: {
    width: '100%',
    maxHeight: 180,
    objectFit: 'cover',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    display: 'block',
  },
  screenshotUrl: {
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  findingsBlock: { display: 'flex', flexDirection: 'column', gap: '0.75rem' },
  findingsSubtitle: {
    margin: '0 0 0.25rem 0',
    fontSize: '0.6875rem',
    fontWeight: 600,
    letterSpacing: '0.05em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
  },
  findingCard: {
    padding: '0.75rem 1rem',
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
  },
  findingCardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '0.5rem',
    flexWrap: 'wrap',
  },
  findingTitle: {
    fontWeight: 600,
    fontSize: '0.875rem',
    color: 'var(--text)',
  },
  findingSeverity: {
    fontSize: '0.6875rem',
    fontWeight: 600,
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    padding: '0.2rem 0.5rem',
    borderRadius: 'var(--radius-sm)',
  },
  severity_critical: { background: 'var(--danger)', color: '#fff' },
  severity_high: { background: 'var(--danger)', color: '#fff' },
  severity_medium: { background: 'var(--warn)', color: '#fff' },
  severity_low: { background: 'var(--accent)', color: 'var(--accent-text)' },
  severity_info: { background: 'var(--border)', color: 'var(--text-muted)' },
  findingTemplate: {
    marginTop: '0.35rem',
    fontSize: '0.75rem',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  findingSynopsis: {
    marginTop: '0.35rem',
    fontSize: '0.8rem',
    color: 'var(--text-muted)',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
  },
  empty: { margin: 0, color: 'var(--text-muted)', fontSize: '0.875rem' },
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
