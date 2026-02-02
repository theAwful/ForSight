import { useState, useRef, useEffect } from 'react'
import { api } from './api'

const PHASE_LABELS = {
  pre_engagement: 'Pre-engagement',
  recon: 'Recon',
  nmap: 'Nmap',
  enumeration: 'Enumeration',
  web_host: 'Web host',
  exploitation: 'Exploitation',
  reporting: 'Reporting',
}

const PHASES_REQUIRING_NMAP = new Set(['enumeration', 'web_host'])

export default function Checklist({ projectId, checklist, onRun, onStatusChange, nmapDone = false }) {
  const [running, setRunning] = useState(null)
  const [runningPhase, setRunningPhase] = useState(null)
  const [updating, setUpdating] = useState(null)
  const [collapsed, setCollapsed] = useState(() => new Set())
  const collapsedInitialized = useRef(false)
  useEffect(() => {
    if (checklist?.length && !collapsedInitialized.current) {
      collapsedInitialized.current = true
      setCollapsed(new Set(checklist.map((p, i) => p?.phase ?? `phase-${i}`)))
    }
  }, [checklist])
  const toggleCollapsed = (phaseKey) => {
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(phaseKey)) next.delete(phaseKey)
      else next.add(phaseKey)
      return next
    })
  }

  const run = async (runnerKey, phase) => {
    setRunning(runnerKey)
    try {
      await api.jobs.run(projectId, runnerKey, {})
      onRun()
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
    } finally {
      setRunningPhase(null)
    }
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

  if (!checklist?.length) return <div style={{ color: 'var(--text-muted)' }}>Loading checklist…</div>

  const phases = Array.isArray(checklist) ? checklist : []

  return (
    <div style={styles.wrapper} className="checklist-wrapper">
      <p style={styles.workflowHint}>
        <strong>Workflow:</strong> Upload/paste ROE (IPs + domains). Run Recon/OSINT on domains only. Run Nmap on ROE IPs — Enumeration and Web host use nmap results for ports. Download workpapers from the Reporting tab.
      </p>
      {phases.map((phase, idx) => {
        const phaseKey = phase?.phase ?? `phase-${idx}`
        const items = Array.isArray(phase?.items) ? phase.items : []
        const runnerCount = items.filter((i) => i?.runner_key).length
        const anyInProgress = items.some((i) => i?.status === 'in_progress')
        const isCollapsed = collapsed.has(phaseKey)
        const requiresNmap = PHASES_REQUIRING_NMAP.has(phaseKey)
        const phaseDisabled = requiresNmap && !nmapDone
        const total = items.length
        const done = items.filter((i) => i?.status === 'completed' || i?.status === 'skipped').length
        const progressPct = total > 0 ? Math.round((done / total) * 100) : 0
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
              <h2 style={styles.phaseTitle}>
                {PHASE_LABELS[phaseKey] ?? phaseKey}
              </h2>
              {total > 0 && (
                <div style={styles.progressWrap} onClick={(e) => e.stopPropagation()}>
                  <div style={styles.progressTrack} title={`${done}/${total} tasks`}>
                    <div style={{ ...styles.progressFill, width: `${progressPct}%` }} />
                  </div>
                  <span style={styles.progressLabel}>{done}/{total}</span>
                </div>
              )}
              {runnerCount > 0 && (
                <>
                  {phaseDisabled && (
                    <span style={styles.phaseDisabledHint} title="Run the Nmap section first">Requires Nmap</span>
                  )}
                  <button
                    className={phaseDisabled ? '' : 'btn-primary'}
                    onClick={(e) => { e.stopPropagation(); runPhase(phaseKey) }}
                    disabled={runningPhase === phaseKey || anyInProgress || phaseDisabled}
                    style={{ ...styles.runAllBtn, ...(phaseDisabled ? styles.runAllBtnDisabled : {}) }}
                  >
                    {runningPhase === phaseKey ? 'Starting…' : anyInProgress ? 'Running…' : phaseDisabled ? 'Run Nmap first' : `Run all (${runnerCount})`}
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
              {items.map((item) => (
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
                    <span style={styles.desc}>{item.description}</span>
                    {item.runner_key && (
                      <button
                        onClick={() => run(item.runner_key, phaseKey)}
                        disabled={running === item.runner_key || item.status === 'in_progress' || phaseDisabled}
                        style={{ ...styles.runBtn, ...(phaseDisabled ? styles.runBtnDisabled : {}) }}
                        title={phaseDisabled ? 'Run the Nmap section first' : ''}
                      >
                        {running === item.runner_key
                          ? 'Starting…'
                          : item.status === 'in_progress'
                            ? 'Running…'
                            : phaseDisabled
                              ? 'Nmap first'
                              : 'Run'}
                      </button>
                    )}
                  </div>
                  {item.tools?.length > 0 && (
                    <div style={styles.tools}>Tools: {item.tools.join(', ')}</div>
                  )}
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
            ))}
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
  phase: { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1rem', transition: 'box-shadow 0.15s ease' },
  workflowHint: { fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '1rem', lineHeight: 1.5 },
  phaseHeader: { display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem', cursor: 'pointer', userSelect: 'none', transition: 'opacity 0.15s ease' },
  collapseIcon: { fontSize: '0.75rem', color: 'var(--text-muted)', flexShrink: 0 },
  phaseTitle: { margin: 0, fontSize: '1rem', fontWeight: 600, color: 'var(--text)', flex: '1 1 auto', minWidth: 0 },
  progressWrap: { display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 },
  progressTrack: { width: 64, height: 6, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' },
  progressFill: { height: '100%', background: 'var(--accent)', borderRadius: 3, transition: 'width 0.25s ease' },
  progressLabel: { fontSize: '0.75rem', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums', minWidth: '2.5ch' },
  runAllBtn: { fontSize: '0.9rem' },
  runAllBtnDisabled: { background: 'var(--border)', color: 'var(--text-muted)', cursor: 'not-allowed' },
  phaseDisabledHint: { fontSize: '0.75rem', color: 'var(--text-muted)', marginRight: '0.5rem' },
  runBtnDisabled: { background: 'var(--border)', color: 'var(--text-muted)', cursor: 'not-allowed' },
  toggle: { marginBottom: '0.5rem', fontSize: '0.85rem', color: 'var(--text-muted)' },
  list: { listStyle: 'none', margin: 0, padding: 0 },
  item: { padding: '0.75rem 0', borderTop: '1px solid var(--border)' },
  itemTop: { display: 'flex', alignItems: 'flex-start', gap: '0.5rem', flexWrap: 'wrap' },
  status: { color: 'var(--text-muted)', flexShrink: 0 },
  statusDone: { color: 'var(--accent)' },
  statusProgress: { color: 'var(--warn)' },
  desc: { flex: 1, minWidth: 200 },
  runBtn: { background: 'var(--accent)', color: 'var(--accent-text)', flexShrink: 0 },
  tools: { fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' },
  actions: { display: 'flex', gap: '0.25rem', marginTop: '0.5rem', flexWrap: 'wrap' },
  statusBtn: { fontSize: '0.8rem', padding: '0.25rem 0.5rem', background: 'transparent', color: 'var(--text-muted)' },
  statusBtnActive: { color: 'var(--accent)' },
  downloadRow: { marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border)' },
  downloadBtn: { display: 'inline-block', padding: '0.5rem 1rem', background: 'var(--accent)', color: 'var(--accent-text)', borderRadius: 'var(--radius)', fontWeight: 500, textDecoration: 'none', transition: 'background-color 0.15s ease, filter 0.15s ease' },
}
