import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from './api'

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_LABELS = ['Info', 'Low', 'Medium', 'High', 'Critical']

const SEV_COLORS = {
  4: { bg: 'rgba(220,38,38,0.12)',   text: '#f87171', border: 'rgba(220,38,38,0.3)',   dot: '#ef4444' },
  3: { bg: 'rgba(234,88,12,0.12)',   text: '#fb923c', border: 'rgba(234,88,12,0.3)',   dot: '#f97316' },
  2: { bg: 'rgba(217,119,6,0.12)',   text: '#fbbf24', border: 'rgba(217,119,6,0.3)',   dot: '#f59e0b' },
  1: { bg: 'rgba(37,99,235,0.10)',   text: '#60a5fa', border: 'rgba(37,99,235,0.25)',  dot: '#3b82f6' },
  0: { bg: 'rgba(100,116,139,0.10)', text: '#94a3b8', border: 'rgba(100,116,139,0.2)',dot: '#64748b' },
}

const sevLabel = (s) => SEV_LABELS[Number(s ?? 0)] ?? 'Info'
const sevCfg   = (s) => SEV_COLORS[Number(s ?? 0)] ?? SEV_COLORS[0]

function SeverityPill({ severity, size = 'sm' }) {
  const cfg = sevCfg(severity)
  return (
    <span style={{
      display: 'inline-block',
      padding: size === 'lg' ? '4px 14px' : '2px 9px',
      borderRadius: 4,
      fontSize: size === 'lg' ? '0.8rem' : '0.7rem',
      fontWeight: 700,
      letterSpacing: '0.06em',
      textTransform: 'uppercase',
      background: cfg.bg,
      color: cfg.text,
      border: `1px solid ${cfg.border}`,
      whiteSpace: 'nowrap',
      flexShrink: 0,
    }}>
      {sevLabel(severity)}
    </span>
  )
}

function StatusChip({ status }) {
  const s = (status || '').toLowerCase()
  const cfg =
    s === 'completed' ? { bg: 'rgba(5,150,105,0.12)',  text: '#34d399' } :
    s === 'running'   ? { bg: 'rgba(79,70,229,0.12)',   text: '#818cf8' } :
    s === 'paused'    ? { bg: 'rgba(217,119,6,0.12)',   text: '#fbbf24' } :
                        { bg: 'rgba(100,116,139,0.1)',  text: '#94a3b8' }
  return (
    <span style={{
      display: 'inline-block', padding: '2px 9px', borderRadius: 4,
      fontSize: '0.75rem', fontWeight: 600, background: cfg.bg, color: cfg.text,
    }}>
      {s ? s.charAt(0).toUpperCase() + s.slice(1) : 'Unknown'}
    </span>
  )
}

function formatLastRun(ts) {
  if (!ts) return 'Never'
  try { return new Date(ts * 1000).toLocaleString() } catch { return String(ts) }
}

// ── Small reusable bits ───────────────────────────────────────────────────────

function BackButton({ onClick, label = '← Back' }) {
  return (
    <button type="button" onClick={onClick} style={S.backBtn}>{label}</button>
  )
}

function DetailSection({ title, children }) {
  return (
    <section style={S.section}>
      <h4 style={S.sectionHeading}>{title}</h4>
      {children}
    </section>
  )
}

function PreBlock({ children, terminal = false }) {
  return (
    <pre style={terminal ? S.termBlock : S.preBlock}>{children}</pre>
  )
}

function MetaRow({ label, children }) {
  if (!children && children !== 0) return null
  return (
    <div style={S.metaRow}>
      <span style={S.metaLabel}>{label}</span>
      <span style={S.metaValue}>{children}</span>
    </div>
  )
}

// ── Vuln detail panel ─────────────────────────────────────────────────────────
// Receives a fully-enriched vuln object (with all plugin fields + affected_hosts array)

function VulnDetail({ vuln, onBack, scanName }) {
  const scrollRef = useRef(null)

  useEffect(() => {
    // Scroll the panel itself to top, not the page
    if (scrollRef.current) scrollRef.current.scrollTop = 0
  }, [vuln?.plugin_id])

  if (!vuln) return null

  const cfg = sevCfg(vuln.severity)
  const cves = vuln.cve
    ? (Array.isArray(vuln.cve) ? vuln.cve : String(vuln.cve).split(',').map(s => s.trim()).filter(Boolean))
    : []

  return (
    <div style={S.detailRoot} ref={scrollRef}>
      {/* Breadcrumb nav */}
      <div style={S.detailNav}>
        <BackButton onClick={onBack} label="← Vulnerabilities" />
        <span style={S.breadcrumb}>
          {scanName}
          <span style={S.breadcrumbSep}>/</span>
          {vuln.plugin_name || `Plugin ${vuln.plugin_id}`}
        </span>
      </div>

      {/* Title row */}
      <div style={{ ...S.detailTitleRow, borderLeftColor: cfg.dot }}>
        <SeverityPill severity={vuln.severity} size="lg" />
        <h2 style={S.detailTitle}>{vuln.plugin_name || `Plugin ${vuln.plugin_id}`}</h2>
      </div>

      {vuln.synopsis && (
        <p style={S.synopsis}>{vuln.synopsis}</p>
      )}

      {/* Two-column layout: main | sidebar */}
      <div style={S.detailLayout}>

        {/* ── Main column ── */}
        <div style={S.detailMain}>
          {vuln.description && (
            <DetailSection title="Description">
              <PreBlock>{vuln.description}</PreBlock>
            </DetailSection>
          )}

          {vuln.solution && (
            <DetailSection title="Solution">
              <PreBlock>{vuln.solution}</PreBlock>
            </DetailSection>
          )}

          {/* Per-host plugin output */}
          {vuln.host_outputs && vuln.host_outputs.length > 0 && (
            <DetailSection title={`Plugin Output (${vuln.host_outputs.length} host${vuln.host_outputs.length > 1 ? 's' : ''})`}>
              {vuln.host_outputs.map((ho, i) => (
                <div key={i} style={S.hostOutputBlock}>
                  <div style={S.hostOutputHeader}>
                    <code style={S.mono}>{ho.host}</code>
                    {ho.port && (
                      <span style={S.portTag}>{ho.port}/{ho.protocol || 'tcp'}</span>
                    )}
                  </div>
                  {ho.output && <PreBlock terminal>{ho.output}</PreBlock>}
                </div>
              ))}
            </DetailSection>
          )}

          {/* Fallback single plugin output */}
          {!vuln.host_outputs?.length && vuln.plugin_output && (
            <DetailSection title="Plugin Output">
              <PreBlock terminal>{vuln.plugin_output}</PreBlock>
            </DetailSection>
          )}

          {/* Affected hosts */}
          {vuln.affected_hosts?.length > 0 && (
            <DetailSection title={`Affected Hosts (${vuln.affected_hosts.length})`}>
              <div style={S.chipGroup}>
                {vuln.affected_hosts.map((h, i) => (
                  <span key={i} style={S.hostChip}>{h}</span>
                ))}
              </div>
            </DetailSection>
          )}

          {/* References */}
          {vuln.see_also && (
            <DetailSection title="References">
              <PreBlock>{vuln.see_also}</PreBlock>
            </DetailSection>
          )}
        </div>

        {/* ── Sidebar ── */}
        <aside style={S.detailSidebar}>
          <div style={S.sideCard}>
            <div style={S.sideCardTitle}>Details</div>
            <MetaRow label="Plugin ID"><code style={S.mono}>{vuln.plugin_id}</code></MetaRow>
            <MetaRow label="Severity"><SeverityPill severity={vuln.severity} /></MetaRow>
            {vuln.risk_factor && <MetaRow label="Risk Factor">{vuln.risk_factor}</MetaRow>}
            {(vuln.cvss_score || vuln.cvss3_base_score) && (
              <MetaRow label="CVSS">
                {vuln.cvss3_base_score
                  ? <span>{vuln.cvss3_base_score} <span style={S.dimTag}>v3</span></span>
                  : vuln.cvss_score}
              </MetaRow>
            )}
            {vuln.cvss3_vector && <MetaRow label="Vector"><code style={{ ...S.mono, fontSize: '0.7rem', wordBreak: 'break-all' }}>{vuln.cvss3_vector}</code></MetaRow>}
            {vuln.port && <MetaRow label="Port">{vuln.port}/{vuln.protocol || 'tcp'}</MetaRow>}
            {vuln.family && <MetaRow label="Family">{vuln.family}</MetaRow>}
            {vuln.exploit_available && (
              <MetaRow label="Exploit">
                <span style={{ color: '#f87171', fontWeight: 600 }}>Available</span>
              </MetaRow>
            )}
            {vuln.exploitability_ease && <MetaRow label="Exploitability">{vuln.exploitability_ease}</MetaRow>}
          </div>

          {cves.length > 0 && (
            <div style={{ ...S.sideCard, marginTop: 12 }}>
              <div style={S.sideCardTitle}>CVEs</div>
              <div style={S.cveList}>
                {cves.map((c, i) => (
                  <a
                    key={i}
                    href={`https://nvd.nist.gov/vuln/detail/${c}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={S.cveLink}
                  >
                    {c}
                  </a>
                ))}
              </div>
            </div>
          )}

          {vuln.patch_publication_date && (
            <div style={{ ...S.sideCard, marginTop: 12 }}>
              <div style={S.sideCardTitle}>Timeline</div>
              {vuln.plugin_publication_date && <MetaRow label="Published">{vuln.plugin_publication_date}</MetaRow>}
              {vuln.patch_publication_date && <MetaRow label="Patch">{vuln.patch_publication_date}</MetaRow>}
              {vuln.plugin_modification_date && <MetaRow label="Updated">{vuln.plugin_modification_date}</MetaRow>}
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}

// ── Host detail panel ─────────────────────────────────────────────────────────

function HostDetail({ host, onBack, scanName, onVulnClick }) {
  const scrollRef = useRef(null)

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0
  }, [host?.host_ip])

  if (!host) return null

  const vulns = (host.vulns || []).slice().sort((a, b) => Number(b.severity) - Number(a.severity))
  const sevCounts = [4, 3, 2, 1, 0].map(n => ({
    n, label: SEV_LABELS[n], count: vulns.filter(v => Number(v.severity) === n).length,
  })).filter(x => x.count > 0)

  const hostLabel = host.name || host.host_ip

  return (
    <div style={S.detailRoot} ref={scrollRef}>
      <div style={S.detailNav}>
        <BackButton onClick={onBack} label="← Hosts" />
        <span style={S.breadcrumb}>
          {scanName}
          <span style={S.breadcrumbSep}>/</span>
          {hostLabel}
        </span>
      </div>

      <h2 style={{ ...S.detailTitle, marginBottom: 4 }}>{hostLabel}</h2>
      {host.name && host.host_ip && host.name !== host.host_ip && (
        <div style={S.hostIpSubtitle}>{host.host_ip}</div>
      )}

      {/* Severity summary pills */}
      <div style={S.sevPillRow}>
        {sevCounts.map(({ n, label, count }) => {
          const cfg = SEV_COLORS[n]
          return (
            <span key={n} style={{ ...S.sevSummaryPill, background: cfg.bg, color: cfg.text, border: `1px solid ${cfg.border}` }}>
              {count} {label}
            </span>
          )
        })}
      </div>

      {/* Host properties if available */}
      {host.properties && Object.keys(host.properties).length > 0 && (
        <div style={{ ...S.sideCard, marginBottom: 20, display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(200px,1fr))', gap: '4px 16px' }}>
          {Object.entries(host.properties).map(([k, v]) => (
            <MetaRow key={k} label={k}>{String(v)}</MetaRow>
          ))}
        </div>
      )}

      {/* Vuln table for this host */}
      <div style={S.tableWrap}>
        <table style={S.table}>
          <thead>
            <tr>
              <th style={S.th}>Severity</th>
              <th style={S.th}>Vulnerability</th>
              <th style={S.th}>Port</th>
              <th style={S.th}>Plugin ID</th>
            </tr>
          </thead>
          <tbody>
            {vulns.length === 0 ? (
              <tr><td colSpan={4} style={{ ...S.td, color: 'var(--text-muted)' }}>No findings for this host.</td></tr>
            ) : vulns.map((v, i) => (
              <tr
                key={v.plugin_id ?? i}
                style={S.vulnRow}
                onClick={() => onVulnClick(v, host)}
              >
                <td style={{ ...S.td, width: 100 }}><SeverityPill severity={v.severity} /></td>
                <td style={{ ...S.td, ...S.vulnName }}>{v.plugin_name || `Plugin ${v.plugin_id}`}</td>
                <td style={{ ...S.td, width: 90, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                  {v.port ? `${v.port}/${v.protocol || 'tcp'}` : '—'}
                </td>
                <td style={{ ...S.td, width: 100, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{v.plugin_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── ImportFindings: vuln list + host list with real drill-down ────────────────

function ImportFindings({ projectId, importMeta, onBack }) {
  const [detail, setDetail]           = useState(null)
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState(null)
  const [subView, setSubView]         = useState('vulns') // 'vulns' | 'hosts'
  const [search, setSearch]           = useState('')
  const [sevFilter, setSevFilter]     = useState(null)   // null = all, 0-4 = filter
  const [selectedVuln, setSelectedVuln] = useState(null)
  const [selectedHost, setSelectedHost] = useState(null)

  useEffect(() => {
    setLoading(true)
    api.nessus.getImport(projectId, importMeta.scan_id)
      .then(setDetail)
      .catch(e => setError(e?.body?.detail || e?.message || 'Failed to load'))
      .finally(() => setLoading(false))
  }, [projectId, importMeta.scan_id])

  if (loading) return <div style={S.muted}>Loading scan details…</div>
  if (error)   return <div style={S.errorBox}>{error}</div>
  if (!detail) return null

  const scanName = detail.scan_name || `Scan ${importMeta.scan_id}`
  const hosts    = detail.hosts || []

  // Build deduplicated vuln list, preserving per-host plugin output
  const vulnMap = new Map()
  for (const host of hosts) {
    for (const v of host.vulns || []) {
      const key = v.plugin_id
      if (!vulnMap.has(key)) {
        vulnMap.set(key, { ...v, affected_hosts: [], host_outputs: [] })
      }
      const entry = vulnMap.get(key)
      const hostLabel = host.name || host.host_ip
      if (!entry.affected_hosts.includes(hostLabel)) {
        entry.affected_hosts.push(hostLabel)
      }
      if (v.plugin_output) {
        entry.host_outputs.push({
          host: hostLabel,
          port: v.port,
          protocol: v.protocol,
          output: v.plugin_output,
        })
      }
      // Merge any richer fields from later hosts if current entry is sparse
      for (const field of ['synopsis','description','solution','cvss_score','cvss3_base_score',
                            'cvss3_vector','cve','risk_factor','family','see_also',
                            'exploit_available','exploitability_ease','patch_publication_date',
                            'plugin_publication_date','plugin_modification_date']) {
        if (!entry[field] && v[field]) entry[field] = v[field]
      }
    }
  }

  const allVulns = [...vulnMap.values()].sort((a, b) => Number(b.severity) - Number(a.severity))

  const sevCounts = [4, 3, 2, 1, 0].map(n => ({
    n, label: SEV_LABELS[n], count: allVulns.filter(v => Number(v.severity) === n).length
  }))

  const filtered = allVulns.filter(v => {
    const matchesSev  = sevFilter === null || Number(v.severity) === sevFilter
    const matchesText = !search.trim() ||
      (v.plugin_name || '').toLowerCase().includes(search.toLowerCase()) ||
      String(v.plugin_id).includes(search) ||
      (v.cve || '').toLowerCase().includes(search.toLowerCase())
    return matchesSev && matchesText
  })

  // ── Vuln detail view ──
  if (selectedVuln) {
    return (
      <VulnDetail
        vuln={selectedVuln}
        scanName={scanName}
        onBack={() => setSelectedVuln(null)}
      />
    )
  }

  // ── Host detail view ──
  if (selectedHost) {
    return (
      <HostDetail
        host={selectedHost}
        scanName={scanName}
        onBack={() => setSelectedHost(null)}
        onVulnClick={(v, host) => {
          // Enrich the single-host vuln with full data from vulnMap
          const enriched = vulnMap.get(v.plugin_id) || { ...v, affected_hosts: [host.name || host.host_ip], host_outputs: [] }
          setSelectedVuln(enriched)
          setSelectedHost(null)
        }}
      />
    )
  }

  return (
    <div>
      {/* Header */}
      <div style={S.findingsHeader}>
        <BackButton onClick={onBack} label="← All scans" />
        <span style={S.findingsScanName}>{scanName}</span>
      </div>

      {/* Severity summary bar */}
      <div style={S.sevBar}>
        <button
          type="button"
          style={{ ...S.sevBarItem, ...(sevFilter === null ? S.sevBarItemActive : {}) }}
          onClick={() => setSevFilter(null)}
        >
          <span style={S.sevBarCount}>{allVulns.length}</span>
          <span style={S.sevBarLabel}>All</span>
        </button>
        {[4,3,2,1,0].map(n => {
          const cfg = SEV_COLORS[n]
          const count = sevCounts.find(x => x.n === n)?.count ?? 0
          if (count === 0) return null
          return (
            <button
              key={n}
              type="button"
              onClick={() => setSevFilter(sevFilter === n ? null : n)}
              style={{
                ...S.sevBarItem,
                ...(sevFilter === n ? { background: cfg.bg, borderColor: cfg.border } : {}),
              }}
            >
              <span style={{ ...S.sevBarCount, color: cfg.text }}>{count}</span>
              <span style={S.sevBarLabel}>{SEV_LABELS[n]}</span>
            </button>
          )
        })}
      </div>

      {/* Sub-tabs */}
      <div style={S.subTabs}>
        <button
          type="button"
          style={{ ...S.subTab, ...(subView === 'vulns' ? S.subTabActive : {}) }}
          onClick={() => setSubView('vulns')}
        >
          Vulnerabilities
          <span style={S.tabBadge}>{allVulns.length}</span>
        </button>
        <button
          type="button"
          style={{ ...S.subTab, ...(subView === 'hosts' ? S.subTabActive : {}) }}
          onClick={() => setSubView('hosts')}
        >
          Hosts
          <span style={S.tabBadge}>{hosts.length}</span>
        </button>
      </div>

      {/* ── Vulnerabilities tab ── */}
      {subView === 'vulns' && (
        <div>
          <div style={S.toolbar}>
            <input
              type="search"
              placeholder="Search by name, plugin ID, or CVE…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={S.searchInput}
            />
            <span style={S.muted}>
              {filtered.length !== allVulns.length
                ? `${filtered.length} of ${allVulns.length}`
                : `${allVulns.length} findings`}
            </span>
            {(search || sevFilter !== null) && (
              <button
                type="button"
                style={S.clearBtn}
                onClick={() => { setSearch(''); setSevFilter(null) }}
              >
                Clear filters
              </button>
            )}
          </div>

          <div style={S.tableWrap}>
            <table style={S.table}>
              <thead>
                <tr>
                  <th style={{ ...S.th, width: 100 }}>Severity</th>
                  <th style={S.th}>Vulnerability</th>
                  <th style={{ ...S.th, width: 80 }}>Plugin</th>
                  <th style={{ ...S.th, width: 80, textAlign: 'right' }}>Hosts</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ ...S.td, color: 'var(--text-muted)', textAlign: 'center', padding: '24px 14px' }}>
                      No vulnerabilities match your filters.
                    </td>
                  </tr>
                ) : filtered.map((v, i) => (
                  <tr
                    key={v.plugin_id ?? i}
                    style={S.vulnRow}
                    onClick={() => setSelectedVuln(v)}
                  >
                    <td style={S.td}><SeverityPill severity={v.severity} /></td>
                    <td style={{ ...S.td, ...S.vulnName }}>
                      {v.plugin_name || `Plugin ${v.plugin_id}`}
                      {v.cve && (
                        <span style={S.cveBadge}>
                          {Array.isArray(v.cve) ? v.cve[0] : String(v.cve).split(',')[0].trim()}
                          {(Array.isArray(v.cve) ? v.cve.length : String(v.cve).split(',').length) > 1 && '+'}
                        </span>
                      )}
                    </td>
                    <td style={{ ...S.td, color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.8rem' }}>{v.plugin_id}</td>
                    <td style={{ ...S.td, textAlign: 'right', color: 'var(--text-muted)' }}>
                      {v.affected_hosts?.length ?? 0}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Hosts tab ── */}
      {subView === 'hosts' && (
        <div>
          <div style={S.tableWrap}>
            <table style={S.table}>
              <thead>
                <tr>
                  <th style={S.th}>Host</th>
                  <th style={{ ...S.th, width: 80, textAlign: 'center' }}>Crit</th>
                  <th style={{ ...S.th, width: 80, textAlign: 'center' }}>High</th>
                  <th style={{ ...S.th, width: 80, textAlign: 'center' }}>Med</th>
                  <th style={{ ...S.th, width: 80, textAlign: 'center' }}>Low</th>
                  <th style={{ ...S.th, width: 80, textAlign: 'center' }}>Info</th>
                  <th style={{ ...S.th, width: 80, textAlign: 'right' }}>Total</th>
                </tr>
              </thead>
              <tbody>
                {hosts.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ ...S.td, color: 'var(--text-muted)', textAlign: 'center', padding: '24px 14px' }}>
                      No hosts found.
                    </td>
                  </tr>
                ) : hosts.map((h, i) => {
                  const hVulns = h.vulns || []
                  const counts = [4,3,2,1,0].map(n => hVulns.filter(v => Number(v.severity) === n).length)
                  return (
                    <tr
                      key={h.host_ip || i}
                      style={S.vulnRow}
                      onClick={() => setSelectedHost(h)}
                    >
                      <td style={{ ...S.td, fontFamily: 'monospace', fontWeight: 500 }}>
                        {h.name && h.name !== h.host_ip
                          ? <span>{h.name} <span style={S.dimTag}>{h.host_ip}</span></span>
                          : h.host_ip || h.name}
                      </td>
                      {counts.map((c, idx) => (
                        <td key={idx} style={{ ...S.td, textAlign: 'center' }}>
                          {c > 0
                            ? <span style={{ color: SEV_COLORS[4-idx]?.text, fontWeight: 600 }}>{c}</span>
                            : <span style={{ color: 'var(--text-muted)' }}>—</span>
                          }
                        </td>
                      ))}
                      <td style={{ ...S.td, textAlign: 'right', fontWeight: 600 }}>{hVulns.length}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

// ── ImportedResults: list of imported scans ───────────────────────────────────

function ImportedResults({ projectId, imports, onDelete }) {
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
        <p style={{ margin: '0 0 6px', fontWeight: 600, color: 'var(--text)' }}>No imported results yet</p>
        <p style={S.muted}>
          Switch to <strong>Available scans</strong> and click <strong>Import results</strong> after a scan completes.
        </p>
      </div>
    )
  }

  return (
    <div style={S.tableWrap}>
      <table style={S.table}>
        <thead>
          <tr>
            <th style={S.th}>Scan name</th>
            <th style={{ ...S.th, textAlign: 'center' }}>Hosts</th>
            <th style={{ ...S.th, textAlign: 'center' }}>Findings</th>
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
              <td style={{ ...S.td, textAlign: 'center' }}>{imp.hosts_count ?? 0}</td>
              <td style={{ ...S.td, textAlign: 'center' }}>{imp.vulns_count ?? 0}</td>
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

// ── AvailableScans ────────────────────────────────────────────────────────────

function AvailableScans({
  projectId, scans, webLaunchInfo, launching, pausing, stopping, importing, deleting, templates,
  onLaunch, onPause, onStop, onImport, onDelete,
  showCreate, handleShowCreateToggle,
  createName, setCreateName, createTemplateUuid, setCreateTemplateUuid,
  createExtraTargets, setCreateExtraTargets,
  creating, creatingViaWeb, createError, onCreateAPI, onCreateWeb,
}) {
  return (
    <div>
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
                const key       = s.id ?? s.name ?? idx
                const name      = s.name ?? `Scan ${s.id}`
                const status    = (s.status || '').toLowerCase()
                const isRunning = status === 'running'
                const isPaused  = status === 'paused'
                return (
                  <tr key={key} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ ...S.td, fontWeight: 500 }}>{name}</td>
                    <td style={S.td}><StatusChip status={s.status} /></td>
                    <td style={{ ...S.td, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                      {formatLastRun(s.last_modification_date)}
                    </td>
                    <td style={{ ...S.td, textAlign: 'right' }}>
                      <div style={S.actionGroup}>
                        {!isRunning && !isPaused && (
                          <button type="button" style={{ ...S.actionBtn, ...S.primaryBtn }}
                            disabled={launching === key || (!webLaunchInfo?.available && !s.id)}
                            onClick={() => onLaunch(s.id, name)}>
                            {launching === key ? 'Launching…' : 'Launch'}
                          </button>
                        )}
                        {isRunning && webLaunchInfo?.available && (
                          <button type="button" style={S.actionBtn}
                            disabled={pausing === name}
                            onClick={() => onPause(name)}>
                            {pausing === name ? 'Pausing…' : 'Pause'}
                          </button>
                        )}
                        {isPaused && webLaunchInfo?.available && (
                          <button type="button" style={{ ...S.actionBtn, ...S.primaryBtn }}
                            disabled={launching === key}
                            onClick={() => onLaunch(s.id, name)}>
                            {launching === key ? 'Resuming…' : 'Resume'}
                          </button>
                        )}
                        {(isRunning || isPaused) && webLaunchInfo?.available && (
                          <button type="button" style={{ ...S.actionBtn, ...S.dangerOutlineBtn }}
                            disabled={stopping === name}
                            onClick={() => onStop(name)}>
                            {stopping === name ? 'Stopping…' : 'Stop'}
                          </button>
                        )}
                        {webLaunchInfo?.open_url && (
                          <button type="button" style={S.actionBtn}
                            onClick={() => window.open(webLaunchInfo.open_url, '_blank', 'noopener,noreferrer')}>
                            Open ↗
                          </button>
                        )}
                        <button type="button" style={S.actionBtn}
                          disabled={importing === s.id || !s.id}
                          onClick={() => onImport(s.id)}>
                          {importing === s.id ? 'Importing…' : 'Import results'}
                        </button>
                        {webLaunchInfo?.available && (
                          <button type="button" style={{ ...S.actionBtn, ...S.dangerOutlineBtn }}
                            disabled={deleting === key}
                            onClick={() => onDelete(s.id, name)}>
                            {deleting === key ? 'Deleting…' : 'Trash'}
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

      {/* Create section */}
      <div style={S.createSection}>
        <button type="button" style={S.toggleCreateBtn} onClick={handleShowCreateToggle}>
          {showCreate ? '− Hide' : '+ New scan'}
        </button>
        {showCreate && (
          <div style={S.createForm}>
            {createError && <div style={S.errorBox}>{createError}</div>}
            <div style={S.formRow}>
              <label style={S.label}>Scan name</label>
              <input type="text" value={createName} onChange={e => setCreateName(e.target.value)}
                placeholder="e.g. ForSight scan" style={S.input} />
            </div>
            <div style={S.formRow}>
              <label style={S.label}>Template</label>
              <select value={createTemplateUuid} onChange={e => setCreateTemplateUuid(e.target.value)} style={S.input}>
                <option value="">— Select template —</option>
                {templates.map((t, i) => {
                  const val = t.uuid || t.title || t.name || `tpl-${i}`
                  const lbl = t.title || t.name || val
                  return <option key={val + i} value={val}>{lbl}{t.category ? ` (${t.category})` : ''}</option>
                })}
              </select>
            </div>
            <div style={S.formRow}>
              <label style={S.label}>Extra targets <span style={S.muted}>(optional)</span></label>
              <textarea value={createExtraTargets} onChange={e => setCreateExtraTargets(e.target.value)}
                placeholder="Additional IPs or hostnames"
                style={{ ...S.input, minHeight: 72, resize: 'vertical' }} />
            </div>
            <div style={S.formActions}>
              <button type="button" style={{ ...S.actionBtn, ...S.primaryBtn }}
                disabled={creating || !createName.trim() || !createTemplateUuid}
                onClick={onCreateAPI}>
                {creating ? 'Creating…' : 'Create (API)'}
              </button>
              {webLaunchInfo?.available && (
                <button type="button" style={S.actionBtn}
                  disabled={creatingViaWeb || !createName.trim()}
                  onClick={onCreateWeb}>
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

export default function Nessus({ projectId }) {
  const [configured,      setConfigured]      = useState(false)
  const [webLaunchInfo,   setWebLaunchInfo]   = useState(null)
  const [scans,           setScans]           = useState([])
  const [imports,         setImports]         = useState([])
  const [loading,         setLoading]         = useState(true)
  const [error,           setError]           = useState(null)
  const [view,            setView]            = useState('imported')
  const [launching,       setLaunching]       = useState(null)
  const [pausing,         setPausing]         = useState(null)
  const [stopping,        setStopping]        = useState(null)
  const [importing,       setImporting]       = useState(null)
  const [deleting,        setDeleting]        = useState(null)
  const [templates,       setTemplates]       = useState([])
  const [showCreate,      setShowCreate]      = useState(false)
  const [createName,      setCreateName]      = useState('')
  const [createTemplateUuid, setCreateTemplateUuid] = useState('')
  const [createExtraTargets, setCreateExtraTargets] = useState('')
  const [creating,        setCreating]        = useState(false)
  const [creatingViaWeb,  setCreatingViaWeb]  = useState(false)
  const [createError,     setCreateError]     = useState(null)
  const [statusMsg,       setStatusMsg]       = useState(null)

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
      Promise.resolve([]),
    ])
      .then(([s, i]) => { setScans(s); setImports(i) })
      .catch(e => setError(e?.body?.detail || e?.message || 'Failed to load Nessus data'))
      .finally(() => setLoading(false))
  }, [configured, projectId])

  const handleRefresh = () => { loadImports(); loadScans(true) }

  const handleShowCreateToggle = async () => {
    const opening = !showCreate
    setShowCreate(v => !v)
    if (opening && templates.length === 0) {
      try {
        const t = await api.nessus.templatesViaWeb(projectId)
        setTemplates(Array.isArray(t?.templates) ? t.templates : [])
      } catch { /* silent */ }
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
        flash('success', 'Scan launched.')
      } else {
        flash('error', 'Web launch not configured. Set FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD in .env.')
      }
      await loadScans(true)
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Launch failed.')
    } finally { setLaunching(null) }
  }

  const handlePause = async (scanName) => {
    setPausing(scanName)
    try {
      await api.nessus.pauseScanViaWebByName(projectId, scanName)
      flash('success', `Paused "${scanName}".`)
      await loadScans(true)
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Pause failed.')
    } finally { setPausing(null) }
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
    } finally { setStopping(null) }
  }

  const handleImport = async (scanId) => {
    setImporting(scanId)
    try {
      await api.nessus.importScan(projectId, scanId)
      flash('success', 'Import complete. Results merged into Hosts.')
      await loadImports()
    } catch (e) {
      flash('error', e?.body?.detail || e?.message || 'Import failed.')
    } finally { setImporting(null) }
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
    } finally { setDeleting(null) }
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
    if (!createName.trim()) return
    setCreating(true); setCreateError(null)
    try {
      await api.nessus.createScan(projectId, {
        name: createName.trim(),
        template_uuid: '731a8e52-3ea6-a291-ec0a-d2ff0619c19f',
        use_project_targets: true,
        text_targets: createExtraTargets || undefined,
      })
      flash('success', `Scan "${createName}" created.`)
      setCreateName(''); setCreateExtraTargets(''); setShowCreate(false)
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
      await api.nessus.createScanViaWeb(projectId, {
        name: createName.trim(), template_key: createTemplateUuid || 'advanced',
        use_project_targets: true, text_targets: createExtraTargets || undefined,
      })
      flash('success', `Scan "${createName}" created via web.`)
      setCreateName(''); setCreateExtraTargets(''); setShowCreate(false)
      await loadScans(true)
    } catch (e) {
      setCreateError(e?.body?.detail || e?.message || 'Create via web failed.')
    } finally { setCreatingViaWeb(false) }
  }

  // ── Not configured ──────────────────────────────────────────────────────────

  if (!configured && !loading) {
    return (
      <div style={S.notConfigured}>
        <h2 style={{ margin: '0 0 8px', fontSize: '1.1rem', fontWeight: 700 }}>Nessus not configured</h2>
        <p style={{ ...S.muted, marginBottom: 14 }}>
          Set Tenable credentials in <code style={S.inlineCode}>backend/.env</code>:
        </p>
        <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
          {[
            ['FORSIGHT_TENABLE_BASE_URL',   'Nessus URL (default https://127.0.0.1:8834)'],
            ['FORSIGHT_TENABLE_ACCESS_KEY', 'API access key'],
            ['FORSIGHT_TENABLE_SECRET_KEY', 'API secret key'],
            ['FORSIGHT_TENABLE_USERNAME',   'Username (for Selenium launch/create/delete)'],
            ['FORSIGHT_TENABLE_PASSWORD',   'Password (for Selenium)'],
          ].map(([k, v]) => (
            <li key={k} style={{ marginBottom: 6 }}>
              <code style={S.inlineCode}>{k}</code>
              <span style={S.muted}> — {v}</span>
            </li>
          ))}
        </ul>
      </div>
    )
  }

  if (loading && !imports.length) return <div style={S.muted}>Loading Nessus data…</div>

  // ── Main layout ─────────────────────────────────────────────────────────────

  return (
    <div>
      <div style={S.header}>
        <h2 style={S.pageTitle}>Nessus</h2>
        <div style={S.headerActions}>
          <button type="button"
            style={{ ...S.tabPill, ...(view === 'imported' ? S.tabPillActive : {}) }}
            onClick={() => setView('imported')}>
            Imported results
          </button>
          <button type="button"
            style={{ ...S.tabPill, ...(view === 'scans' ? S.tabPillActive : {}) }}
            onClick={() => setView('scans')}>
            Available scans
          </button>
          <button type="button" style={S.refreshBtn} onClick={handleRefresh}>↻ Refresh</button>
        </div>
      </div>

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

      <div>
        {view === 'imported' && (
          <ImportedResults
            projectId={projectId}
            imports={imports}
            onDelete={handleDeleteImport}
          />
        )}
        {view === 'scans' && (
          <AvailableScans
            projectId={projectId}
            scans={scans}
            webLaunchInfo={webLaunchInfo}
            launching={launching} pausing={pausing} stopping={stopping}
            importing={importing} deleting={deleting}
            templates={templates}
            onLaunch={handleLaunch} onPause={handlePause} onStop={handleStop}
            onImport={handleImport} onDelete={handleDelete}
            showCreate={showCreate} handleShowCreateToggle={handleShowCreateToggle}
            createName={createName} setCreateName={setCreateName}
            createTemplateUuid={createTemplateUuid} setCreateTemplateUuid={setCreateTemplateUuid}
            createExtraTargets={createExtraTargets} setCreateExtraTargets={setCreateExtraTargets}
            creating={creating} creatingViaWeb={creatingViaWeb}
            createError={createError} onCreateAPI={handleCreateAPI} onCreateWeb={handleCreateWeb}
          />
        )}
      </div>
    </div>
  )
}

// ── Styles ────────────────────────────────────────────────────────────────────

const S = {
  // Layout
  header:        { display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 16 },
  pageTitle:     { margin: 0, fontSize: '1.25rem', fontWeight: 700 },
  headerActions: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },

  // Tab pills
  tabPill:       { padding: '5px 14px', borderRadius: 20, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: '0.85rem', cursor: 'pointer', fontWeight: 500 },
  tabPillActive: { background: 'var(--accent)', color: 'var(--accent-text)', borderColor: 'var(--accent)' },
  refreshBtn:    { padding: '5px 12px', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: '0.82rem', borderRadius: 6, cursor: 'pointer' },

  // Flash / error
  flashMsg:  { padding: '10px 14px', borderLeft: '3px solid', borderRadius: '0 6px 6px 0', background: 'var(--surface)', marginBottom: 12, fontSize: '0.875rem', fontWeight: 500 },
  errorBox:  { padding: '10px 14px', background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: 6, color: 'var(--danger)', fontSize: '0.875rem', marginBottom: 12 },

  // Table
  tableWrap: { overflowX: 'auto', borderRadius: 8, border: '1px solid var(--border)' },
  table:     { width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' },
  th:        { padding: '10px 14px', textAlign: 'left', fontWeight: 600, fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', background: 'var(--surface-muted)', borderBottom: '1px solid var(--border)' },
  td:        { padding: '11px 14px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle', color: 'var(--text)' },
  vulnRow:   { cursor: 'pointer', transition: 'background 0.1s' },
  vulnName:  { maxWidth: 480, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },

  // Action buttons
  actionGroup:      { display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end', flexWrap: 'wrap' },
  actionBtn:        { padding: '4px 12px', borderRadius: 5, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.8rem', cursor: 'pointer', fontWeight: 500, whiteSpace: 'nowrap' },
  primaryBtn:       { background: 'var(--primary)', color: 'var(--primary-text)', borderColor: 'transparent' },
  dangerBtn:        { padding: '3px 10px', border: '1px solid rgba(220,38,38,0.4)', background: 'transparent', color: 'var(--danger)', borderRadius: 5, fontSize: '0.78rem', cursor: 'pointer' },
  dangerOutlineBtn: { borderColor: 'rgba(220,38,38,0.4)', color: 'var(--danger)', background: 'transparent' },

  // Severity bar (top of findings)
  sevBar:         { display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' },
  sevBarItem:     { display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '8px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', cursor: 'pointer', minWidth: 64, transition: 'background 0.15s' },
  sevBarItemActive: { background: 'var(--surface-muted)', borderColor: 'var(--border)' },
  sevBarCount:    { fontSize: '1.2rem', fontWeight: 700, lineHeight: 1.2, color: 'var(--text)' },
  sevBarLabel:    { fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginTop: 2 },

  // Sub-tabs (vulns / hosts within a scan)
  subTabs:      { display: 'flex', gap: 2, marginBottom: 16, borderBottom: '1px solid var(--border)' },
  subTab:       { padding: '8px 16px', border: 'none', background: 'transparent', color: 'var(--text-muted)', fontSize: '0.875rem', cursor: 'pointer', borderBottom: '2px solid transparent', display: 'flex', alignItems: 'center', gap: 6 },
  subTabActive: { color: 'var(--text)', borderBottomColor: 'var(--primary)', fontWeight: 600 },
  tabBadge:     { display: 'inline-block', padding: '1px 7px', borderRadius: 10, background: 'var(--surface-muted)', fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-muted)' },

  // Toolbar
  toolbar:     { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' },
  searchInput: { flex: 1, minWidth: 200, maxWidth: 360, padding: '7px 11px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--surface-muted)', color: 'var(--text)', fontSize: '0.875rem' },
  clearBtn:    { padding: '5px 12px', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: '0.8rem', borderRadius: 6, cursor: 'pointer' },

  // CVE badge inline in vuln name
  cveBadge:    { marginLeft: 8, padding: '1px 7px', borderRadius: 4, fontSize: '0.68rem', fontWeight: 600, background: 'rgba(37,99,235,0.10)', color: '#60a5fa', border: '1px solid rgba(37,99,235,0.2)', verticalAlign: 'middle' },

  // Findings header
  findingsHeader:   { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 },
  findingsScanName: { fontWeight: 600, fontSize: '1rem', color: 'var(--text)' },

  // Detail panel (vuln or host)
  detailRoot:    { maxHeight: 'calc(100vh - 160px)', overflowY: 'auto', paddingRight: 4 },
  detailNav:     { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 },
  breadcrumb:    { fontSize: '0.85rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  breadcrumbSep: { margin: '0 6px', opacity: 0.5 },

  detailTitleRow: { display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 10, borderLeft: '3px solid transparent', paddingLeft: 10 },
  detailTitle:    { margin: 0, fontSize: '1.15rem', fontWeight: 700, lineHeight: 1.35, color: 'var(--text)' },
  synopsis:       { margin: '0 0 20px', color: 'var(--text-muted)', fontSize: '0.9rem', lineHeight: 1.6, paddingLeft: 10 },

  detailLayout: { display: 'grid', gridTemplateColumns: '1fr 260px', gap: 24, alignItems: 'start' },
  detailMain:   {},
  detailSidebar: { position: 'sticky', top: 0 },

  // Sections
  section:        { marginBottom: 20 },
  sectionHeading: { margin: '0 0 8px', fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' },

  // Code blocks
  preBlock:  { margin: 0, padding: '12px 14px', background: 'var(--surface-muted)', border: '1px solid var(--border)', borderRadius: 6, fontSize: '0.82rem', lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text)', fontFamily: 'monospace' },
  termBlock: { margin: 0, padding: '12px 14px', background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 6, fontSize: '0.8rem', lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: '#a5f3fc', fontFamily: 'monospace' },

  // Per-host output
  hostOutputBlock:  { marginBottom: 14 },
  hostOutputHeader: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 },
  portTag:          { padding: '1px 8px', borderRadius: 4, background: 'var(--surface-muted)', border: '1px solid var(--border)', fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'monospace' },

  // Chip groups
  chipGroup: { display: 'flex', flexWrap: 'wrap', gap: 6 },
  hostChip:  { padding: '3px 10px', borderRadius: 4, background: 'var(--surface-muted)', border: '1px solid var(--border)', fontSize: '0.78rem', fontFamily: 'monospace', color: 'var(--text)' },

  // Sidebar cards
  sideCard:      { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 14px' },
  sideCardTitle: { fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 10 },
  metaRow:       { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, paddingBottom: 7, marginBottom: 7, borderBottom: '1px solid var(--border)', fontSize: '0.82rem' },
  metaLabel:     { color: 'var(--text-muted)', flexShrink: 0 },
  metaValue:     { color: 'var(--text)', textAlign: 'right', wordBreak: 'break-word' },

  // CVE list
  cveList: { display: 'flex', flexDirection: 'column', gap: 4 },
  cveLink: { fontSize: '0.82rem', color: '#60a5fa', textDecoration: 'none', fontFamily: 'monospace' },

  // Host detail
  hostIpSubtitle: { color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.85rem', marginBottom: 12 },
  sevPillRow:     { display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' },
  sevSummaryPill: { padding: '4px 12px', borderRadius: 6, fontSize: '0.8rem', fontWeight: 600 },

  // Misc
  mono:          { fontFamily: 'monospace', fontSize: '0.82rem' },
  dimTag:        { color: 'var(--text-muted)', fontSize: '0.8rem' },
  muted:         { color: 'var(--text-muted)', fontSize: '0.875rem', margin: 0 },
  backBtn:       { padding: '5px 12px', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', borderRadius: 6, fontSize: '0.82rem', cursor: 'pointer', fontWeight: 500, flexShrink: 0 },
  emptyBox:      { padding: '32px 24px', textAlign: 'center', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 },
  notConfigured: { padding: '24px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 },
  inlineCode:    { padding: '1px 6px', background: 'var(--surface-muted)', borderRadius: 4, fontFamily: 'monospace', fontSize: '0.82rem' },

  // Create form
  createSection:   { marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)' },
  toggleCreateBtn: { padding: '6px 14px', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text)', borderRadius: 6, fontSize: '0.85rem', cursor: 'pointer', fontWeight: 500 },
  createForm:      { marginTop: 14, padding: '16px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 560 },
  formRow:         { display: 'flex', flexDirection: 'column', gap: 4 },
  label:           { fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)' },
  input:           { padding: '7px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--surface-muted)', color: 'var(--text)', fontSize: '0.875rem', width: '100%', boxSizing: 'border-box' },
  formActions:     { display: 'flex', gap: 8, flexWrap: 'wrap' },
}
