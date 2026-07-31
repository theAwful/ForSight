import { useState, useEffect, useMemo, useCallback } from 'react'
import { api } from './api'
import ConfirmModal from './ConfirmModal'

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function normSev(s) {
  const v = (s ?? '').toString().toLowerCase()
  if (v === '4' || v === 'critical') return 'critical'
  if (v === '3' || v === 'high')     return 'high'
  if (v === '2' || v === 'medium')   return 'medium'
  if (v === '1' || v === 'low')      return 'low'
  return 'info'
}

const SEV_CFG = {
  critical: { bg: 'rgba(220,38,38,0.12)',   text: '#f87171', border: 'rgba(220,38,38,0.28)'   },
  high:     { bg: 'rgba(234,88,12,0.12)',   text: '#fb923c', border: 'rgba(234,88,12,0.28)'   },
  medium:   { bg: 'rgba(217,119,6,0.12)',   text: '#fbbf24', border: 'rgba(217,119,6,0.28)'   },
  low:      { bg: 'rgba(37,99,235,0.10)',   text: '#60a5fa', border: 'rgba(37,99,235,0.22)'   },
  info:     { bg: 'rgba(100,116,139,0.10)', text: '#94a3b8', border: 'rgba(100,116,139,0.18)' },
}

function SevPill({ sev }) {
  const cfg = SEV_CFG[sev] ?? SEV_CFG.info
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 3,
      fontSize: '0.67rem', fontWeight: 700, letterSpacing: '0.06em',
      textTransform: 'uppercase', whiteSpace: 'nowrap',
      background: cfg.bg, color: cfg.text, border: `1px solid ${cfg.border}`,
    }}>
      {sev}
    </span>
  )
}

// ── Data helpers ──────────────────────────────────────────────────────────────

function findingLabel(f) {
  if (f?.info?.name) return f.info.name
  if (f?.template) return f.template.replace(/^[^/]+\//, '').replace(/[-_]/g, ' ')
  return 'Finding'
}

function byPortBlocks(host) {
  const byPort = host?.by_port && typeof host.by_port === 'object' ? host.by_port : {}
  return Object.entries(byPort).sort(([a], [b]) => (Number(a) || 0) - (Number(b) || 0))
}

function allScreenshots(host) {
  return byPortBlocks(host).flatMap(([portKey, block]) =>
    (block.screenshots || []).map(s => ({ portKey, ...s }))
  )
}

function allNucleiFindings(host) {
  return byPortBlocks(host).flatMap(([portKey, block]) =>
    (block.findings || []).map(f => ({ portKey, ...f }))
  ).sort((a, b) => (SEV_ORDER[normSev(a?.info?.severity)] ?? 4) - (SEV_ORDER[normSev(b?.info?.severity)] ?? 4))
}

function allNessusFindings(host) {
  return (host?.nessus_findings || [])
    .slice()
    .sort((a, b) => Number(b.severity ?? 0) - Number(a.severity ?? 0))
}

// Risk indicator for sidebar — highest-priority signal only
function hostRisk(host) {
  const nessus = allNessusFindings(host)
  const nuclei = allNucleiFindings(host)

  const topNessus = nessus[0] ? normSev(nessus[0].severity) : null
  const topNuclei = nuclei[0] ? normSev(nuclei[0]?.info?.severity) : null

  const top = [topNessus, topNuclei]
    .filter(Boolean)
    .sort((a, b) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9))[0]

  if (top) return SEV_CFG[top].text
  const ports = host?.ports_detail?.length || 0
  if (ports > 0) return '#60a5fa'
  return 'var(--border-strong)'
}

// ── Tab definitions ───────────────────────────────────────────────────────────

function buildTabs(host) {
  const ports   = host?.ports_detail?.length ?? 0
  const screens = allScreenshots(host).length
  const nuclei  = allNucleiFindings(host).length
  const nessus  = allNessusFindings(host).length

  return [
    { id: 'ports',   label: 'Ports',       count: ports,   show: true   },
    { id: 'screens', label: 'Screenshots', count: screens, show: screens > 0 },
    { id: 'nuclei',  label: 'Nuclei',      count: nuclei,  show: nuclei > 0  },
    { id: 'nessus',  label: 'Nessus',      count: nessus,  show: nessus > 0  },
  ].filter(t => t.show)
}

// ── Ports tab ─────────────────────────────────────────────────────────────────

function PortsTab({ host }) {
  const ports = host?.ports_detail || []

  if (!ports.length) {
    return <Empty message="No port data yet. Run Nmap to populate." />
  }

  return (
    <div style={S.tableWrap}>
      <table style={S.table}>
        <thead>
          <tr>
            <th style={S.th}>Port</th>
            <th style={S.th}>Proto</th>
            <th style={S.th}>State</th>
            <th style={S.th}>Service</th>
            <th style={S.th}>Product / Version</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((p, i) => (
            <tr key={i} style={S.tr}>
              <td style={{ ...S.td, ...S.mono, fontWeight: 600 }}>{p.port}</td>
              <td style={{ ...S.td, color: 'var(--text-muted)' }}>{p.protocol || 'tcp'}</td>
              <td style={S.td}>
                <span style={{
                  fontSize: '0.7rem', fontWeight: 600, letterSpacing: '0.04em',
                  color: p.state === 'open' ? '#34d399' : 'var(--text-muted)',
                }}>
                  {p.state || 'open'}
                </span>
              </td>
              <td style={S.td}>{p.service || <span style={{ color: 'var(--text-faint)' }}>—</span>}</td>
              <td style={{ ...S.td, color: 'var(--text-muted)' }}>
                {[p.product, p.version].filter(Boolean).join(' ') || <span style={{ color: 'var(--text-faint)' }}>—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Screenshots tab ───────────────────────────────────────────────────────────

function ScreenshotsTab({ host, projectId, onLightbox }) {
  const shots = allScreenshots(host)

  if (!shots.length) return <Empty message="No screenshots captured." />

  return (
    <div style={S.screenshotGrid}>
      {shots.map((s, i) => {
        const url = s.filename ? api.screenshots.url(projectId, s.filename) : ''
        const caption = s.url || s.filename || `Port ${s.portKey}`
        return (
          <div key={i} style={S.screenshotCard}>
            <button
              type="button"
              style={S.thumbBtn}
              onClick={() => url && onLightbox(url)}
              title="View full size"
            >
              <img src={url} alt="" style={S.thumbImg} loading="lazy" />
              <div style={S.thumbOverlay}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" />
                </svg>
              </div>
            </button>
            <div style={S.thumbMeta}>
              <code style={S.thumbPort}>{s.portKey}</code>
              <span style={S.thumbCaption} title={caption}>{caption}</span>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Nuclei tab ────────────────────────────────────────────────────────────────

function NucleiTab({ host }) {
  const findings = allNucleiFindings(host)
  const [expanded, setExpanded] = useState(null)

  if (!findings.length) return <Empty message="No Nuclei findings." />

  return (
    <div style={S.tableWrap}>
      <table style={S.table}>
        <thead>
          <tr>
            <th style={{ ...S.th, width: 90 }}>Severity</th>
            <th style={S.th}>Finding</th>
            <th style={{ ...S.th, width: 80 }}>Port</th>
            <th style={{ ...S.th, width: 200 }}>Template</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const sev = normSev(f?.info?.severity)
            const label = findingLabel(f)
            const isOpen = expanded === i
            return [
              <tr
                key={`r-${i}`}
                style={{ ...S.tr, cursor: 'pointer' }}
                onClick={() => setExpanded(isOpen ? null : i)}
              >
                <td style={S.td}><SevPill sev={sev} /></td>
                <td style={{ ...S.td, fontWeight: 500 }}>{label}</td>
                <td style={{ ...S.td, ...S.mono, color: 'var(--text-muted)' }}>
                  {f.portKey === '0' ? '—' : f.portKey}
                </td>
                <td style={{ ...S.td, ...S.mono, fontSize: '0.72rem', color: 'var(--text-faint)' }}>
                  {f?.template?.replace(/^[^/]+\//, '') || '—'}
                </td>
              </tr>,
              isOpen && (f?.info?.description || f?.info?.reference) ? (
                <tr key={`e-${i}`} style={{ background: 'var(--surface-muted)' }}>
                  <td colSpan={4} style={{ padding: '10px 14px 12px', borderBottom: '1px solid var(--border)' }}>
                    {f.info.description && (
                      <p style={{ margin: '0 0 6px', fontSize: '0.82rem', color: 'var(--text)', lineHeight: 1.6 }}>
                        {f.info.description}
                      </p>
                    )}
                    {f.info.reference && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {(Array.isArray(f.info.reference) ? f.info.reference : [f.info.reference]).map((r, ri) => (
                          <a key={ri} href={r} target="_blank" rel="noopener noreferrer" style={{ display: 'block', color: 'var(--accent)', marginTop: 2 }}>{r}</a>
                        ))}
                      </div>
                    )}
                  </td>
                </tr>
              ) : null,
            ]
          })}
        </tbody>
      </table>
    </div>
  )
}

// ── Nessus tab ────────────────────────────────────────────────────────────────

function NessusTab({ host }) {
  const findings = allNessusFindings(host)
  const [expanded, setExpanded] = useState(null)

  if (!findings.length) return <Empty message="No Nessus findings. Import a scan on the Nessus tab." />

  return (
    <div style={S.tableWrap}>
      <table style={S.table}>
        <thead>
          <tr>
            <th style={{ ...S.th, width: 90 }}>Severity</th>
            <th style={S.th}>Plugin</th>
            <th style={{ ...S.th, width: 100 }}>Port</th>
            <th style={{ ...S.th, width: 80 }}>CVE</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const sev = normSev(f.severity)
            const isOpen = expanded === i
            const cves = f.cve
              ? (Array.isArray(f.cve) ? f.cve : String(f.cve).split(',').map(s => s.trim()).filter(Boolean))
              : []
            return [
              <tr
                key={`r-${i}`}
                style={{ ...S.tr, cursor: (f.synopsis || f.description) ? 'pointer' : 'default' }}
                onClick={() => (f.synopsis || f.description) && setExpanded(isOpen ? null : i)}
              >
                <td style={S.td}><SevPill sev={sev} /></td>
                <td style={{ ...S.td, fontWeight: 500 }}>
                  {f.plugin_name || `Plugin ${f.plugin_id}`}
                </td>
                <td style={{ ...S.td, ...S.mono, color: 'var(--text-muted)' }}>
                  {f.port ? `${f.port}/${f.protocol || 'tcp'}` : '—'}
                </td>
                <td style={{ ...S.td, ...S.mono, fontSize: '0.72rem' }}>
                  {cves.length > 0
                    ? <span style={{ color: 'var(--accent)' }}>{cves[0]}{cves.length > 1 ? ` +${cves.length - 1}` : ''}</span>
                    : <span style={{ color: 'var(--text-faint)' }}>—</span>}
                </td>
              </tr>,
              isOpen ? (
                <tr key={`e-${i}`} style={{ background: 'var(--surface-muted)' }}>
                  <td colSpan={4} style={{ padding: '10px 14px 14px', borderBottom: '1px solid var(--border)' }}>
                    {f.synopsis && (
                      <p style={{ margin: '0 0 8px', fontSize: '0.82rem', color: 'var(--text)', lineHeight: 1.6, fontWeight: 500 }}>
                        {f.synopsis}
                      </p>
                    )}
                    {f.solution && (
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                        <strong style={{ color: 'var(--text)', display: 'block', marginBottom: 2 }}>Solution</strong>
                        {f.solution}
                      </div>
                    )}
                    {cves.length > 1 && (
                      <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {cves.map((c, ci) => (
                          <a key={ci} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer"
                            style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
                            {c}
                          </a>
                        ))}
                      </div>
                    )}
                  </td>
                </tr>
              ) : null,
            ]
          })}
        </tbody>
      </table>
    </div>
  )
}

// ── Empty state ───────────────────────────────────────────────────────────────

function Empty({ message }) {
  return (
    <div style={{ padding: '32px 0', textAlign: 'center', color: 'var(--text-faint)', fontSize: '0.85rem' }}>
      {message}
    </div>
  )
}

// ── Lightbox ──────────────────────────────────────────────────────────────────

function Lightbox({ url, onClose }) {
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div style={S.lightboxOverlay} onClick={onClose}>
      <button type="button" style={S.lightboxClose} onClick={onClose} aria-label="Close">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M18 6L6 18M6 6l12 12" />
        </svg>
      </button>
      <img
        src={url}
        alt="Screenshot"
        style={S.lightboxImg}
        onClick={e => e.stopPropagation()}
      />
    </div>
  )
}

// ── Recon tab (raw tool outputs) ──────────────────────────────────────────────

function formatBytes(n) {
  if (!n || n < 1024) return `${n || 0} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function ReconViewer({ title, content, onClose }) {
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div style={S.reconOverlay} onClick={onClose} role="dialog" aria-modal="true" aria-label={title}>
      <div style={S.reconModal} onClick={e => e.stopPropagation()}>
        <div style={S.reconModalHead}>
          <h3 style={S.reconModalTitle}>{title}</h3>
          <button type="button" style={S.reconModalClose} onClick={onClose} aria-label="Close">×</button>
        </div>
        <pre style={S.reconModalBody}>{content || '(empty)'}</pre>
      </div>
    </div>
  )
}

function ReconTab({ projectId }) {
  const [artifacts, setArtifacts] = useState([])
  const [loading, setLoading] = useState(true)
  const [viewer, setViewer] = useState(null)
  const [loadingKey, setLoadingKey] = useState(null)
  const [expandedShodan, setExpandedShodan] = useState(false)

  const fetchRecon = useCallback(() => {
    if (!projectId) return
    api.projects.recon(projectId)
      .then(data => setArtifacts(Array.isArray(data) ? data : []))
      .catch(() => setArtifacts([]))
      .finally(() => setLoading(false))
  }, [projectId])

  useEffect(() => { fetchRecon() }, [fetchRecon])
  useEffect(() => {
    const t = setInterval(fetchRecon, 8000)
    return () => clearInterval(t)
  }, [fetchRecon])

  const openArtifact = async (key, child, label) => {
    const loadId = child ? `${key}:${child}` : key
    setLoadingKey(loadId)
    try {
      const data = await api.projects.reconContent(projectId, key, child)
      setViewer({ title: data?.label || label || key, content: data?.content || '' })
    } catch (e) {
      window.alert(e?.body?.detail || e?.message || 'Failed to load recon output')
    } finally {
      setLoadingKey(null)
    }
  }

  if (loading) {
    return <div style={{ color: 'var(--text-muted)', padding: 24, fontSize: '0.875rem' }}>Loading recon…</div>
  }

  const availableCount = artifacts.filter(a => a.available).length

  return (
    <>
      {availableCount === 0 && (
        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: '0 0 16px' }}>
          Run recon checklist items (WHOIS, Subfinder, Shodan, …) to populate these outputs.
        </p>
      )}
      <div style={S.reconGrid}>
        {artifacts.map(a => {
          const isShodan = a.key === 'shodan'
          return (
            <div key={a.key} style={{ ...S.reconCard, ...(a.available ? {} : S.reconCardEmpty) }}>
              <button
                type="button"
                style={S.reconCardBtn}
                disabled={!a.available || (isShodan && !a.children?.length)}
                onClick={() => {
                  if (isShodan) { setExpandedShodan(v => !v); return }
                  openArtifact(a.key, null, a.label)
                }}
                title={a.available ? `Open ${a.label}` : 'Not run yet'}
              >
                <div style={S.reconCardIcon} aria-hidden>
                  {isShodan ? '◎' : a.key === 'whois' ? '¶' : '▤'}
                </div>
                <div style={S.reconCardText}>
                  <span style={S.reconCardLabel}>{a.label}</span>
                  <span style={S.reconCardDesc}>{a.description}</span>
                  <span style={S.reconCardMeta}>
                    {a.available
                      ? (isShodan ? `${a.children?.length || 0} IPs · ${formatBytes(a.size)}` : formatBytes(a.size))
                      : 'Not available'}
                    {loadingKey === a.key ? ' · loading…' : ''}
                    {isShodan && a.available ? (expandedShodan ? ' · hide' : ' · expand') : ''}
                  </span>
                </div>
              </button>
              {isShodan && expandedShodan && a.children?.length > 0 && (
                <div style={S.shodanChildren}>
                  {a.children.map(c => (
                    <button
                      key={c.key}
                      type="button"
                      style={S.shodanChildBtn}
                      disabled={loadingKey === `shodan:${c.key}`}
                      onClick={() => openArtifact('shodan', c.key, c.label)}
                    >
                      <code style={S.shodanChildIp}>{c.label}</code>
                      <span style={S.shodanChildSize}>{formatBytes(c.size)}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
      {viewer && (
        <ReconViewer title={viewer.title} content={viewer.content} onClose={() => setViewer(null)} />
      )}
    </>
  )
}

// ── Host detail panel ─────────────────────────────────────────────────────────

function HostDetail({ host, projectId, onExclude, onLightbox }) {
  const [activeTab, setActiveTab] = useState('ports')

  // Reset tab when host changes, pick best default
  useEffect(() => {
    if (!host) return
    const tabs = buildTabs(host)
    if (!tabs.find(t => t.id === activeTab)) {
      setActiveTab(tabs[0]?.id ?? 'ports')
    }
  }, [host?.host])

  if (!host) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: 300 }}>
        <span style={{ color: 'var(--text-faint)', fontSize: '0.875rem' }}>Select a host to view details.</span>
      </div>
    )
  }

  const tabs = buildTabs(host)
  const ports   = host?.ports_detail?.length ?? 0
  const nessus  = allNessusFindings(host)
  const nuclei  = allNucleiFindings(host)
  const screens = allScreenshots(host)

  // Top risk signal
  const topRisk = [
    ...nessus.slice(0, 1).map(f => normSev(f.severity)),
    ...nuclei.slice(0, 1).map(f => normSev(f?.info?.severity)),
  ].sort((a, b) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9))[0]

  return (
    <div style={S.detail}>
      {/* Header */}
      <div style={S.detailHead}>
        <div style={S.detailHeadLeft}>
          {topRisk && (
            <span style={{
              width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
              background: SEV_CFG[topRisk]?.text, display: 'inline-block',
              boxShadow: `0 0 0 3px ${SEV_CFG[topRisk]?.bg}`,
            }} />
          )}
          <h2 style={S.detailHostname}>{host.host}</h2>
        </div>

        <div style={S.detailHeadRight}>
          {/* Summary badges — clean, no emoji, no cryptic abbreviations */}
          <div style={S.summaryBadges}>
            {ports > 0 && (
              <span style={S.badge}>{ports} {ports === 1 ? 'port' : 'ports'}</span>
            )}
            {screens.length > 0 && (
              <span style={S.badge}>{screens.length} {screens.length === 1 ? 'screenshot' : 'screenshots'}</span>
            )}
            {nuclei.length > 0 && (
              <span style={{ ...S.badge, ...S.badgeWarn }}>
                {nuclei.length} Nuclei {nuclei.length === 1 ? 'finding' : 'findings'}
              </span>
            )}
            {nessus.length > 0 && (
              <span style={{ ...S.badge, ...S.badgeDanger }}>
                {nessus.length} Nessus {nessus.length === 1 ? 'finding' : 'findings'}
              </span>
            )}
          </div>

          <button type="button" style={S.removeBtn} onClick={() => onExclude(host.host)}>
            Remove from list
          </button>
        </div>
      </div>

      {/* Tabs */}
      {tabs.length > 0 && (
        <div style={S.tabStrip}>
          {tabs.map(t => (
            <button
              key={t.id}
              type="button"
              style={{ ...S.tabBtn, ...(activeTab === t.id ? S.tabBtnActive : {}) }}
              onClick={() => setActiveTab(t.id)}
            >
              {t.label}
              {t.count > 0 && (
                <span style={{
                  ...S.tabCount,
                  ...(activeTab === t.id ? S.tabCountActive : {}),
                }}>
                  {t.count}
                </span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Tab content */}
      <div style={S.tabContent}>
        {activeTab === 'ports'   && <PortsTab host={host} />}
        {activeTab === 'screens' && <ScreenshotsTab host={host} projectId={projectId} onLightbox={onLightbox} />}
        {activeTab === 'nuclei'  && <NucleiTab host={host} />}
        {activeTab === 'nessus'  && <NessusTab host={host} />}
      </div>
    </div>
  )
}

// ── Main Hosts component ──────────────────────────────────────────────────────

export default function Hosts({ projectId }) {
  const [pageTab, setPageTab]           = useState('recon')
  const [hosts, setHosts]               = useState([])
  const [selectedIndex, setSelectedIndex] = useState(null)
  const [filter, setFilter]             = useState('')
  const [loading, setLoading]           = useState(true)
  const [lightboxUrl, setLightboxUrl]   = useState(null)
  const [excludeTarget, setExcludeTarget] = useState(null)
  const [excluding, setExcluding]       = useState(false)

  const fetchHosts = useCallback(() => {
    if (!projectId) return
    api.projects.hosts(projectId)
      .then(data => {
        const list = Array.isArray(data) ? data : []
        setHosts(list)
        setLoading(false)
        setSelectedIndex(prev => {
          if (!list.length) return null
          if (prev != null && prev < list.length) return prev
          return list.length > 0 ? 0 : null
        })
      })
      .catch(() => setLoading(false))
  }, [projectId])

  useEffect(() => { fetchHosts() }, [fetchHosts])

  useEffect(() => {
    const t = setInterval(fetchHosts, 5000)
    return () => clearInterval(t)
  }, [fetchHosts])

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return hosts.map((h, i) => ({ h, i }))
    return hosts.map((h, i) => ({ h, i })).filter(({ h }) =>
      (h.host || '').toLowerCase().includes(q)
    )
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
      window.alert(e?.body?.detail || e?.message || 'Failed to remove host')
    } finally {
      setExcluding(false)
    }
  }

  const pageTabs = [
    { id: 'recon', label: 'Recon' },
    { id: 'hosts', label: 'Hosts', count: hosts.length },
  ]

  return (
    <>
      <div style={S.pageTabStrip}>
        {pageTabs.map(t => (
          <button
            key={t.id}
            type="button"
            style={{ ...S.pageTabBtn, ...(pageTab === t.id ? S.pageTabBtnActive : {}) }}
            onClick={() => setPageTab(t.id)}
          >
            {t.label}
            {t.count != null && t.count > 0 && (
              <span style={{
                ...S.tabCount,
                ...(pageTab === t.id ? S.tabCountActive : {}),
              }}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {pageTab === 'recon' && (
        <div style={S.reconWrap}>
          <ReconTab projectId={projectId} />
        </div>
      )}

      {pageTab === 'hosts' && (
        loading ? (
          <div style={{ color: 'var(--text-muted)', padding: 24, fontSize: '0.875rem' }}>Loading hosts…</div>
        ) : !hosts.length ? (
          <div style={{ textAlign: 'center', padding: '56px 24px' }}>
            <p style={{ fontWeight: 600, fontSize: '0.95rem', marginBottom: 6, color: 'var(--text)' }}>No hosts yet</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>Run Nmap to populate the host list.</p>
          </div>
        ) : (
          <div style={S.layout}>
            <aside style={S.sidebar}>
              <div style={S.sidebarHead}>
                <span style={S.sidebarLabel}>Hosts</span>
                <span style={S.sidebarCount}>{hosts.length}</span>
              </div>

              <div style={S.filterWrap}>
                <input
                  type="search"
                  placeholder="Filter hosts…"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  style={S.filterInput}
                  aria-label="Filter hosts"
                />
              </div>

              <ul style={S.hostList} className="hosts-sidebar-list" role="listbox" aria-label="Host list">
                {filtered.length === 0
                  ? <li style={{ padding: '12px 14px', color: 'var(--text-faint)', fontSize: '0.82rem' }}>No match.</li>
                  : filtered.map(({ h, i }) => {
                      const active = selectedIndex === i

                      return (
                        <li key={`${h.host}-${i}`} role="option" aria-selected={active}>
                          <button
                            type="button"
                            style={{ ...S.hostBtn, ...(active ? S.hostBtnActive : {}) }}
                            onClick={() => setSelectedIndex(i)}
                          >
                            <span style={S.hostName}>{h.host}</span>
                          </button>
                        </li>
                      )
                    })
                }
              </ul>
            </aside>

            <main style={S.main}>
              <HostDetail
                host={current}
                projectId={projectId}
                onExclude={setExcludeTarget}
                onLightbox={setLightboxUrl}
              />
            </main>
          </div>
        )
      )}

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

      {lightboxUrl && <Lightbox url={lightboxUrl} onClose={() => setLightboxUrl(null)} />}
    </>
  )
}

// ── Styles ────────────────────────────────────────────────────────────────────

const S = {
  // Two-pane shell
  layout: {
    display: 'grid',
    gridTemplateColumns: '240px 1fr',
    minHeight: 520,
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    overflow: 'hidden',
    background: 'var(--surface)',
  },

  // Host list sidebar
  sidebar: {
    borderRight: '1px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    background: 'var(--surface-muted)',
    minHeight: 0,
  },
  sidebarHead: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '12px 14px', borderBottom: '1px solid var(--border)', flexShrink: 0,
  },
  sidebarLabel: {
    fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em',
    textTransform: 'uppercase', color: 'var(--text-faint)',
  },
  sidebarCount: {
    fontSize: '0.72rem', fontWeight: 600, padding: '1px 7px',
    background: 'var(--border)', borderRadius: 10, color: 'var(--text-muted)',
  },
  filterWrap: { padding: '8px 10px', flexShrink: 0 },
  filterInput: {
    width: '100%', padding: '6px 10px', fontSize: '0.8rem',
    border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
    background: 'var(--surface)', color: 'var(--text)',
  },
  hostList: {
    listStyle: 'none', margin: 0, padding: '4px 6px',
    overflowY: 'auto', flex: 1,
  },
  hostBtn: {
    display: 'flex', alignItems: 'center', gap: 8, width: '100%',
    padding: '8px 10px', background: 'transparent',
    border: '1px solid transparent', borderRadius: 0,
    cursor: 'pointer', textAlign: 'left', marginBottom: 1,
    transition: 'background 0.1s',
    outline: 'none',
    boxShadow: 'none',
  },
  hostBtnActive: {
    background: 'var(--accent-soft)',
    borderColor: 'transparent',
  },
  hostName: {
    fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 600,
    color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
    minWidth: 0,
  },

  // Detail panel
  main: { display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' },
  detail: { display: 'flex', flexDirection: 'column', height: '100%' },

  detailHead: {
    display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
    flexWrap: 'wrap', gap: 12, padding: '16px 20px 14px',
    borderBottom: '1px solid var(--border)', flexShrink: 0,
  },
  detailHeadLeft: { display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 },
  detailHostname: {
    margin: 0, fontSize: '1.05rem', fontWeight: 700,
    fontFamily: 'var(--font-mono)', color: 'var(--text)',
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
  },
  detailHeadRight: {
    display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', flexShrink: 0,
  },

  // Summary badges in header
  summaryBadges: { display: 'flex', gap: 6, flexWrap: 'wrap' },
  badge: {
    padding: '2px 9px', border: '1px solid var(--border)',
    borderRadius: 10, fontSize: '0.72rem', fontWeight: 600,
    color: 'var(--text-muted)', background: 'var(--surface-muted)',
    whiteSpace: 'nowrap',
  },
  badgeWarn: {
    background: 'rgba(217,119,6,0.10)', borderColor: 'rgba(217,119,6,0.28)', color: '#fbbf24',
  },
  badgeDanger: {
    background: 'rgba(220,38,38,0.10)', borderColor: 'rgba(220,38,38,0.28)', color: '#f87171',
  },

  removeBtn: {
    padding: '4px 10px', fontSize: '0.75rem', fontWeight: 500,
    background: 'transparent', border: '1px solid rgba(220,38,38,0.3)',
    color: 'var(--danger)', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
    whiteSpace: 'nowrap',
  },

  // Tab strip
  tabStrip: {
    display: 'flex', gap: 0, borderBottom: '1px solid var(--border)',
    padding: '0 20px', flexShrink: 0, background: 'var(--surface)',
  },
  tabBtn: {
    display: 'flex', alignItems: 'center', gap: 6,
    padding: '9px 14px', background: 'transparent', border: 'none',
    borderBottom: '2px solid transparent', color: 'var(--text-muted)',
    fontSize: '0.8125rem', fontWeight: 500, cursor: 'pointer',
    transition: 'color 0.15s, border-color 0.15s', borderRadius: 0,
    marginBottom: -1,
  },
  tabBtnActive: {
    color: 'var(--accent)',
    borderBottomColor: 'var(--accent)',
    fontWeight: 600,
  },
  tabCount: {
    display: 'inline-block', padding: '1px 6px', borderRadius: 8,
    background: 'var(--surface-muted)', fontSize: '0.68rem',
    fontWeight: 700, color: 'var(--text-faint)',
  },
  tabCountActive: {
    background: 'var(--accent-soft)', color: 'var(--accent)',
  },
  tabContent: { padding: '18px 20px', overflowY: 'auto', flex: 1 },

  // Tables
  tableWrap: {
    overflowX: 'auto', border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)', background: 'var(--surface)',
  },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' },
  th: {
    padding: '8px 12px', textAlign: 'left', fontWeight: 600,
    fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.06em',
    color: 'var(--text-faint)', background: 'var(--surface-muted)',
    borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap',
  },
  td: { padding: '9px 12px', borderBottom: '1px solid var(--border)', color: 'var(--text)', verticalAlign: 'middle' },
  tr: { transition: 'background 0.1s' },
  mono: { fontFamily: 'var(--font-mono)', fontSize: '0.8rem' },

  // Screenshots
  screenshotGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
    gap: 14,
  },
  screenshotCard: { display: 'flex', flexDirection: 'column', gap: 6 },
  thumbBtn: {
    position: 'relative', background: 'none',
    border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
    padding: 0, cursor: 'pointer', overflow: 'hidden',
    transition: 'border-color 0.15s',
  },
  thumbImg: { width: '100%', height: 120, objectFit: 'cover', display: 'block' },
  thumbOverlay: {
    position: 'absolute', inset: 0,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    background: 'rgba(0,0,0,0)', color: 'white', opacity: 0,
    transition: 'opacity 0.15s, background 0.15s',
    // hover handled inline since inline styles can't do :hover
  },
  thumbMeta: {
    display: 'flex', alignItems: 'baseline', gap: 6,
  },
  thumbPort: {
    fontFamily: 'var(--font-mono)', fontSize: '0.68rem',
    color: 'var(--text-faint)', flexShrink: 0,
    padding: '1px 5px', background: 'var(--surface-muted)',
    border: '1px solid var(--border)', borderRadius: 3,
  },
  thumbCaption: {
    fontSize: '0.72rem', color: 'var(--text-muted)',
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
    flex: 1,
  },

  // Lightbox
  lightboxOverlay: {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.92)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    zIndex: 1000, padding: 24,
  },
  lightboxClose: {
    position: 'absolute', top: 16, right: 16,
    background: 'rgba(255,255,255,0.08)',
    border: '1px solid rgba(255,255,255,0.12)',
    color: '#fff', width: 36, height: 36, borderRadius: 8,
    cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
    transition: 'background 0.15s',
  },
  lightboxImg: {
    maxWidth: '95vw', maxHeight: '92vh',
    objectFit: 'contain', borderRadius: 6,
    boxShadow: '0 24px 64px rgba(0,0,0,0.6)',
  },

  pageTabStrip: {
    display: 'flex', gap: 0, borderBottom: '1px solid var(--border)',
    marginBottom: 16, flexShrink: 0,
  },
  pageTabBtn: {
    display: 'flex', alignItems: 'center', gap: 6,
    padding: '10px 16px', background: 'transparent', border: 'none',
    borderBottom: '2px solid transparent', color: 'var(--text-muted)',
    fontSize: '0.875rem', fontWeight: 500, cursor: 'pointer',
    borderRadius: 0, marginBottom: -1,
  },
  pageTabBtnActive: {
    color: 'var(--accent)',
    borderBottomColor: 'var(--accent)',
    fontWeight: 600,
  },
  reconWrap: {
    border: '1px solid var(--border)',
    background: 'var(--surface)',
    minHeight: 320,
    padding: 20,
  },
  reconGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
    gap: 14,
  },
  reconCard: {
    border: '1px solid var(--border)',
    background: 'var(--bg)',
    display: 'flex',
    flexDirection: 'column',
  },
  reconCardEmpty: { opacity: 0.45 },
  reconCardBtn: {
    display: 'flex', alignItems: 'flex-start', gap: 12, width: '100%',
    padding: 14, background: 'transparent', border: 'none', borderRadius: 0,
    cursor: 'pointer', textAlign: 'left', color: 'var(--text)',
  },
  reconCardIcon: {
    width: 36, height: 36, flexShrink: 0, display: 'flex',
    alignItems: 'center', justifyContent: 'center',
    background: 'var(--surface-muted)', border: '1px solid var(--border)',
    fontSize: '1rem', color: 'var(--accent)',
  },
  reconCardText: { display: 'flex', flexDirection: 'column', gap: 3, minWidth: 0 },
  reconCardLabel: { fontWeight: 600, fontSize: '0.9rem', color: 'var(--text)' },
  reconCardDesc: { fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.35 },
  reconCardMeta: { fontSize: '0.7rem', color: 'var(--text-faint)', fontFamily: 'var(--font-mono)', marginTop: 4 },
  shodanChildren: {
    display: 'flex', flexDirection: 'column',
    borderTop: '1px solid var(--border)', maxHeight: 220, overflowY: 'auto',
  },
  shodanChildBtn: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
    padding: '8px 14px', background: 'transparent', border: 'none',
    borderBottom: '1px solid var(--border)', borderRadius: 0, cursor: 'pointer',
    textAlign: 'left', color: 'var(--text)',
  },
  shodanChildIp: { fontFamily: 'var(--font-mono)', fontSize: '0.78rem' },
  shodanChildSize: { fontSize: '0.68rem', color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' },
  reconOverlay: {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.72)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    zIndex: 1000, padding: 24,
  },
  reconModal: {
    width: 'min(860px, 96vw)', maxHeight: '88vh',
    background: 'var(--surface)', border: '1px solid var(--border)',
    display: 'flex', flexDirection: 'column',
    boxShadow: '0 24px 64px rgba(0,0,0,0.45)',
  },
  reconModalHead: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    gap: 12, padding: '12px 16px', borderBottom: '1px solid var(--border)', flexShrink: 0,
  },
  reconModalTitle: {
    margin: 0, fontSize: '0.95rem', fontWeight: 600,
    fontFamily: 'var(--font-mono)', color: 'var(--text)',
  },
  reconModalClose: {
    background: 'transparent', border: '1px solid var(--border)',
    color: 'var(--text-muted)', width: 32, height: 32, borderRadius: 0,
    cursor: 'pointer', fontSize: '1.25rem', lineHeight: 1,
  },
  reconModalBody: {
    margin: 0, padding: 16, overflow: 'auto', flex: 1,
    fontFamily: 'var(--font-mono)', fontSize: '0.78rem', lineHeight: 1.5,
    color: 'var(--text)', background: 'var(--bg)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
  },
}
