import { useState, useRef, useEffect } from 'react'
import { api } from './api'

const PHASE_LABELS = {
  pre_engagement: 'Pre-engagement',
  recon: 'Recon',
  nmap: 'Nmap',
  enumeration: 'Enumeration',
  web_host: 'Web host',
  reporting: 'Reporting',
}

const PHASES_REQUIRING_NMAP = new Set(['enumeration', 'web_host'])

const PRE_GATE_IDS = ['roe_scope', 'roe_comm']

const PRE_ENGAGEMENT_CHECKS = [
  {
    id: 'roe_scope',
    title: 'Scope matches the ROE',
    hint: 'Targets in ForSight match the agreed scope and written rules of engagement.',
  },
  {
    id: 'roe_comm',
    title: 'Client notified',
    hint: 'The client knows active testing has started.',
  },
]

export default function Checklist({ projectId, checklist, onRun, onStatusChange, nmapDone = false }) {
  const [running, setRunning] = useState(null)
  const [runningPhase, setRunningPhase] = useState(null)
  const [updating, setUpdating] = useState(null)
  const [collapsed, setCollapsed] = useState(() => new Set())
  const collapseInitRef = useRef({ projectId: null, done: false })

  const phases = Array.isArray(checklist) ? checklist : []
  const prePhase = phases.find((p) => p.phase === 'pre_engagement')
  const scanPhases = phases.filter((p) => p.phase !== 'pre_engagement')

  const preEngagementDone = PRE_GATE_IDS.every((id) => {
    const it = prePhase?.items?.find((i) => i.id === id)
    return it?.status === 'completed'
  })

  useEffect(() => {
    if (collapseInitRef.current.projectId !== projectId) {
      collapseInitRef.current = { projectId, done: false }
      setCollapsed(new Set())
    }
    if (collapseInitRef.current.done || !checklist?.length) return
    const scan = checklist.filter((p) => p.phase !== 'pre_engagement')
    if (!scan.length) return
    collapseInitRef.current.done = true
    setCollapsed(new Set(scan.map((p, i) => p?.phase ?? `phase-${i}`)))
  }, [projectId, checklist])

  const toggleCollapsed = (phaseKey) => {
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(phaseKey)) next.delete(phaseKey)
      else next.add(phaseKey)
      return next
    })
  }

  const setStatus = async (itemId, status) => {
    setUpdating(itemId)
    try {
      await api.checklist.update(projectId, itemId, { status })
      onStatusChange()
    } finally {
      setUpdating(null)
    }
  }

  const togglePreGate = (itemId, checked) => {
    setStatus(itemId, checked ? 'completed' : 'not_started')
  }

  const run = async (runnerKey) => {
    setRunning(runnerKey)
    try {
      await api.jobs.run(projectId, runnerKey, {})
      onRun()
    } catch (e) {
      window.alert(e?.body?.detail || e?.message || 'Run failed')
    } finally {
      setRunning(null)
    }
  }

  const runPhase = async (phase) => {
    const phaseHasRunners = checklist.find((p) => p.phase === phase)?.items?.some((i) => i.runner_key)
    if (!phaseHasRunners) return
    setRunningPhase(phase)
    try {
      await api.jobs.runPhase(projectId, phase, {})
      onRun()
    } catch (e) {
      window.alert(e?.body?.detail || e?.message || 'Run failed')
    } finally {
      setRunningPhase(null)
    }
  }

  if (!checklist?.length) return <div style={{ color: 'var(--text-muted)' }}>Loading checklist…</div>

  return (
    <div style={styles.wrapper} className="checklist-wrapper">
      <p style={styles.workflowHint}>
        Set scope with ROE, then run phases in order: <strong>Recon</strong> (domains), <strong>Nmap</strong> (IPs). Enumeration and Web need Nmap first. Export a zip from <strong>Reporting</strong>.
      </p>

      <section className="card checklist-pre-gate" style={styles.preGate}>
        <h2 style={styles.preGateTitle}>Before testing</h2>
        <p style={styles.preGateLead}>Confirm both items to unlock scan jobs. You can uncheck to correct a mistake.</p>
        <ul style={styles.preGateList}>
          {PRE_ENGAGEMENT_CHECKS.map(({ id, title, hint }) => {
            const item = prePhase?.items?.find((i) => i.id === id)
            if (!item) return null
            const checked = item.status === 'completed'
            return (
              <li key={id} style={styles.preGateItem}>
                <label style={styles.preCheckLabel}>
                  <input
                    type="checkbox"
                    className="checklist-pre-checkbox"
                    checked={checked}
                    disabled={updating === item.id}
                    onChange={(e) => togglePreGate(item.id, e.target.checked)}
                  />
                  <span style={styles.preCheckBody}>
                    <span style={styles.preCheckTitle}>{title}</span>
                    <span style={styles.preCheckHint}>{hint}</span>
                  </span>
                </label>
              </li>
            )
          })}
        </ul>
        {!preEngagementDone && (
          <p style={styles.preGateBanner}>Scan phases below stay disabled until both boxes are checked.</p>
        )}
      </section>

      {scanPhases.map((phase, idx) => {
        const phaseKey = phase?.phase ?? `phase-${idx}`
        const items = Array.isArray(phase?.items) ? phase.items : []
        const runnerCount = items.filter((i) => i?.runner_key).length
        const anyInProgress = items.some((i) => i?.status === 'in_progress')
        const phaseRunning = anyInProgress || runningPhase === phaseKey
        const isCollapsed = collapsed.has(phaseKey)
        const requiresNmap = PHASES_REQUIRING_NMAP.has(phaseKey)
        const nmapBlocked = requiresNmap && !nmapDone
        const preBlocked = !preEngagementDone
        const phaseDisabled = preBlocked || nmapBlocked
        const total = items.length
        const done = items.filter((i) => i?.status === 'completed' || i?.status === 'skipped').length
        const progressPct = total > 0 ? Math.round((done / total) * 100) : 0

        let blockReason = null
        if (preBlocked) blockReason = 'pre'
        else if (nmapBlocked) blockReason = 'nmap'

        return (
          <section key={phaseKey} className="card checklist-phase" style={styles.phase}>
            <div
              className="phase-header-clickable"
              style={styles.phaseHeader}
              onClick={() => toggleCollapsed(phaseKey)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && toggleCollapsed(phaseKey)}
              aria-expanded={!isCollapsed}
            >
              <span style={styles.collapseIcon}>{isCollapsed ? '▶' : '▼'}</span>
              <h2 style={styles.phaseTitle}>{PHASE_LABELS[phaseKey] ?? phaseKey}</h2>
              {total > 0 && (
                <div style={styles.progressWrap} onClick={(e) => e.stopPropagation()}>
                  <div
                    className={`checklist-progress-track${phaseRunning ? ' checklist-progress-track-active' : ''}`}
                    title={`${done}/${total} tasks`}
                  >
                    {!phaseRunning && <div style={{ ...styles.progressFill, width: `${progressPct}%` }} />}
                    {phaseRunning && (
                      <div style={{ ...styles.progressFill, width: `${progressPct}%`, opacity: 0.35 }} />
                    )}
                  </div>
                  <span style={styles.progressLabel}>{done}/{total}</span>
                </div>
              )}
              {runnerCount > 0 && (
                <>
                  {blockReason === 'nmap' && (
                    <span style={styles.phaseDisabledHint} title="Run the Nmap section first">
                      Requires Nmap
                    </span>
                  )}
                  {blockReason === 'pre' && (
                    <span style={styles.phaseDisabledHint} title="Complete Before testing checkboxes">
                      Pre-engagement
                    </span>
                  )}
                  <button
                    className={phaseDisabled ? '' : 'btn-primary'}
                    onClick={(e) => {
                      e.stopPropagation()
                      runPhase(phaseKey)
                    }}
                    disabled={runningPhase === phaseKey || anyInProgress || phaseDisabled}
                    style={{ ...styles.runAllBtn, ...(phaseDisabled ? styles.runAllBtnDisabled : {}) }}
                  >
                    {runningPhase === phaseKey
                      ? 'Starting…'
                      : anyInProgress
                        ? 'Running…'
                        : blockReason === 'pre'
                          ? 'Check boxes above'
                          : blockReason === 'nmap'
                            ? 'Run Nmap first'
                            : `Run all (${runnerCount})`}
                  </button>
                </>
              )}
            </div>
            {!isCollapsed && (
              <>
                {phaseKey === 'web_host' && runnerCount > 0 && (
                  <p style={styles.toggle}>Uses Nmap web ports when available.</p>
                )}
                <ul style={styles.list}>
                  {items.map((item) => {
                    const itemRunning =
                      item.status === 'in_progress' || (item.runner_key && running === item.runner_key)
                    return (
                      <li key={item.id} style={styles.item}>
                        <div style={styles.itemTop}>
                          <span
                            style={{
                              ...styles.status,
                              ...(item.status === 'completed' ? styles.statusDone : {}),
                              ...(item.status === 'in_progress' ? styles.statusProgress : {}),
                            }}
                            title={item.status}
                          >
                            {item.status === 'completed' ? '✓' : item.status === 'in_progress' ? '…' : '○'}
                          </span>
                          <div style={styles.itemMain}>
                            <span style={styles.serviceTitle}>{item.description}</span>
                            {item.tools?.length > 0 && (
                              <div style={styles.toolsRow}>
                                {item.tools.map((t) => (
                                  <span key={t} className="checklist-tool-pill">
                                    {t}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          {item.runner_key && (
                            <button
                              onClick={() => run(item.runner_key)}
                              disabled={running === item.runner_key || item.status === 'in_progress' || phaseDisabled}
                              style={{ ...styles.runBtn, ...(phaseDisabled ? styles.runBtnDisabled : {}) }}
                              title={
                                blockReason === 'pre'
                                  ? 'Complete Before testing checkboxes first'
                                  : blockReason === 'nmap'
                                    ? 'Run the Nmap section first'
                                    : ''
                              }
                            >
                              {running === item.runner_key
                                ? 'Starting…'
                                : item.status === 'in_progress'
                                  ? 'Running…'
                                  : blockReason === 'pre'
                                    ? 'Locked'
                                    : blockReason === 'nmap'
                                      ? 'Nmap first'
                                      : 'Run'}
                            </button>
                          )}
                        </div>
                        {itemRunning && <div className="checklist-item-running-bar" aria-hidden />}
                        <div style={styles.actions}>
                          {['not_started', 'in_progress', 'completed', 'skipped'].map((s) => (
                            <button
                              key={s}
                              onClick={() => setStatus(item.id, s)}
                              disabled={updating === item.id}
                              style={{
                                ...styles.statusBtn,
                                ...(item.status === s ? styles.statusBtnActive : {}),
                              }}
                            >
                              {s.replace('_', ' ')}
                            </button>
                          ))}
                        </div>
                      </li>
                    )
                  })}
                </ul>
                {phase.phase === 'reporting' && (
                  <div style={styles.downloadRow}>
                    <a
                      href={api.projects.downloadOutputsUrl(projectId)}
                      download="forsight-outputs.zip"
                      className="download-btn"
                      style={styles.downloadBtn}
                    >
                      Download all tool outputs (zip)
                    </a>
                  </div>
                )}
              </>
            )}
          </section>
        )
      })}
    </div>
  )
}

const styles = {
  wrapper: { display: 'flex', flexDirection: 'column', gap: '1.5rem' },
  preGate: {
    padding: '1.1rem 1.25rem',
    borderColor: 'var(--accent)',
    boxShadow: 'var(--shadow-sm)',
  },
  preGateTitle: {
    margin: '0 0 0.35rem 0',
    fontSize: '1rem',
    fontWeight: 600,
    color: 'var(--text)',
  },
  preGateLead: {
    margin: '0 0 1rem 0',
    fontSize: '0.85rem',
    color: 'var(--text-muted)',
    lineHeight: 1.45,
  },
  preGateList: { listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: '0.85rem' },
  preGateItem: { margin: 0 },
  preCheckLabel: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.75rem',
    cursor: 'pointer',
    margin: 0,
  },
  preCheckBody: { display: 'flex', flexDirection: 'column', gap: '0.2rem', minWidth: 0 },
  preCheckTitle: { fontWeight: 600, fontSize: '0.9rem', color: 'var(--text)' },
  preCheckHint: { fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.4 },
  preGateBanner: {
    margin: '1rem 0 0 0',
    padding: '0.5rem 0.75rem',
    fontSize: '0.8rem',
    color: 'var(--text-muted)',
    background: 'var(--surface-muted)',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border-light)',
  },
  phase: { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1rem', transition: 'box-shadow 0.15s ease, opacity 0.2s ease' },
  workflowHint: { fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '1rem', lineHeight: 1.5 },
  phaseHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    flexWrap: 'wrap',
    marginBottom: '0.5rem',
    cursor: 'pointer',
    userSelect: 'none',
    transition: 'opacity 0.15s ease',
  },
  collapseIcon: { fontSize: '0.75rem', color: 'var(--text-muted)', flexShrink: 0 },
  phaseTitle: { margin: 0, fontSize: '1rem', fontWeight: 600, color: 'var(--text)', flex: '1 1 auto', minWidth: 0 },
  progressWrap: { display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 },
  progressFill: {
    height: '100%',
    background: 'var(--accent)',
    borderRadius: 3,
    transition: 'width 0.25s ease',
    position: 'relative',
    zIndex: 1,
  },
  progressLabel: { fontSize: '0.75rem', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums', minWidth: '2.5ch' },
  runAllBtn: { fontSize: '0.9rem' },
  runAllBtnDisabled: { background: 'var(--border)', color: 'var(--text-muted)', cursor: 'not-allowed' },
  phaseDisabledHint: { fontSize: '0.75rem', color: 'var(--text-muted)', marginRight: '0.5rem' },
  runBtnDisabled: { background: 'var(--border)', color: 'var(--text-muted)', cursor: 'not-allowed' },
  toggle: { marginBottom: '0.5rem', fontSize: '0.85rem', color: 'var(--text-muted)' },
  list: { listStyle: 'none', margin: 0, padding: 0 },
  item: { padding: '0.75rem 0', borderTop: '1px solid var(--border)' },
  itemTop: { display: 'flex', alignItems: 'flex-start', gap: '0.5rem', flexWrap: 'wrap' },
  status: { color: 'var(--text-muted)', flexShrink: 0, marginTop: '0.15rem' },
  statusDone: { color: 'var(--accent)' },
  statusProgress: { color: 'var(--warn)' },
  itemMain: { flex: 1, minWidth: 200 },
  serviceTitle: { display: 'block', fontWeight: 500, color: 'var(--text)', lineHeight: 1.35 },
  toolsRow: { marginTop: '0.35rem' },
  runBtn: { background: 'var(--accent)', color: 'var(--accent-text)', flexShrink: 0 },
  actions: { display: 'flex', gap: '0.25rem', marginTop: '0.5rem', flexWrap: 'wrap' },
  statusBtn: { fontSize: '0.8rem', padding: '0.25rem 0.5rem', background: 'transparent', color: 'var(--text-muted)' },
  statusBtnActive: { color: 'var(--accent)' },
  downloadRow: { marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border)' },
  downloadBtn: {
    display: 'inline-block',
    padding: '0.5rem 1rem',
    background: 'var(--accent)',
    color: 'var(--accent-text)',
    borderRadius: 'var(--radius)',
    fontWeight: 500,
    textDecoration: 'none',
    transition: 'background-color 0.15s ease, filter 0.15s ease',
  },
}
