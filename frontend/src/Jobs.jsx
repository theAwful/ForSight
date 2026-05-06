import { useState, useEffect, useCallback } from 'react'
import { api } from './api'

/**
 * Jobs tab — lists all scan jobs with expandable output.
 * Keeps the original structure that was working.
 * Fixes: black-on-black terminal text, live badge shown for finished jobs.
 */
export default function Jobs({ projectId, jobs, onRefresh }) {
  const [output, setOutput]           = useState(null)   // { jobId, text, runnerKey }
  const [loadingOutput, setLoading]   = useState(null)
  const [stopping, setStopping]       = useState(null)
  const [deleting, setDeleting]       = useState(null)
  const [cleaningUp, setCleaningUp]   = useState(false)
  const [screenshots, setScreenshots] = useState([])
  const [previewUrl, setPreviewUrl]   = useState(null)

  // Guard: filter out any null/undefined entries the API might return
  const safeJobs = Array.isArray(jobs) ? jobs.filter(Boolean) : []

  const isOutputJobRunning = output
    ? (safeJobs.find((j) => j.id === output.jobId)?.status === 'running')
    : false

  // Poll output while a running job is expanded
  useEffect(() => {
    if (!output?.jobId || !isOutputJobRunning) return
    const interval = setInterval(async () => {
      try {
        const text = await api.jobs.output(projectId, output.jobId, 500)
        setOutput((prev) => prev?.jobId === output.jobId ? { ...prev, text } : prev)
      } catch {
        // ignore
      }
    }, 1500)
    return () => clearInterval(interval)
  }, [projectId, output?.jobId, isOutputJobRunning])

  const showOutput = async (job) => {
    if (output?.jobId === job.id) { setOutput(null); setScreenshots([]); return }
    setLoading(job.id)
    try {
      const text = await api.jobs.output(projectId, job.id)
      setOutput({ jobId: job.id, text, runnerKey: job.runner_key })
      if (job.runner_key === 'web_gowitness') {
        const shots = await api.screenshots.list(projectId).catch(() => [])
        setScreenshots(Array.isArray(shots) ? shots : [])
      } else {
        setScreenshots([])
      }
    } catch {
      setOutput({ jobId: job.id, text: '(Failed to load output)', runnerKey: job.runner_key })
    } finally {
      setLoading(null)
    }
  }

  const stopJob = async (id) => {
    setStopping(id)
    try { await api.jobs.stop(projectId, id); onRefresh() }
    catch (e) { window.alert(e?.body?.detail || e?.message || 'Stop failed') }
    finally { setStopping(null) }
  }

  const removeJob = async (id) => {
    setDeleting(id)
    try { await api.jobs.delete(projectId, id); if (output?.jobId === id) setOutput(null); onRefresh() }
    catch (e) { window.alert(e?.body?.detail || e?.message || 'Remove failed') }
    finally { setDeleting(null) }
  }

  const cleanUpCompleted = useCallback(async () => {
    setCleaningUp(true)
    const done = safeJobs.filter((j) => ['completed', 'failed'].includes(j.status))
    await Promise.allSettled(done.map((j) => api.jobs.delete(projectId, j.id)))
    setCleaningUp(false)
    onRefresh()
  }, [projectId, safeJobs, onRefresh])

  if (!safeJobs.length) {
    return <div style={styles.empty}>No scan jobs yet. Run a checklist item from the Checklist tab.</div>
  }

  const completedOrFailed = safeJobs.filter((j) => ['completed', 'failed'].includes(j.status)).length

  // Sort newest first
  const sorted = [...safeJobs].sort((a, b) => {
    const ta = a.started_at ? new Date(a.started_at).getTime() : 0
    const tb = b.started_at ? new Date(b.started_at).getTime() : 0
    return tb - ta
  })

  return (
    <div style={styles.wrapper}>
      {completedOrFailed > 0 && (
        <div style={styles.cleanupRow}>
          <button onClick={cleanUpCompleted} disabled={cleaningUp} style={styles.cleanupBtn}>
            {cleaningUp ? 'Cleaning…' : `Remove ${completedOrFailed} completed/failed job(s)`}
          </button>
        </div>
      )}
      <ul style={styles.list}>
        {sorted.map((j) => (
          <li key={j.id} style={styles.item}>
            <div style={styles.row}>
              {/* Status dot */}
              <span style={{ ...styles.dot, background: dotColor(j.status) }} title={j.status} />
              <span style={styles.runner}>{j.runner_key}</span>
              <span style={{ ...styles.status, color: statusColor(j.status) }}>{j.status}</span>
              <span style={styles.time}>
                {j.started_at ? new Date(j.started_at).toLocaleString() : '—'}
              </span>
              <button
                onClick={() => showOutput(j)}
                disabled={loadingOutput === j.id}
                style={styles.btn}
              >
                {loadingOutput === j.id ? '…' : output?.jobId === j.id ? 'Hide' : 'Output'}
              </button>
              {(j.status === 'running' || j.status === 'pending') && (
                <button
                  onClick={() => stopJob(j.id)}
                  disabled={stopping === j.id}
                  style={styles.stopBtn}
                >
                  {stopping === j.id ? 'Stopping…' : 'Stop'}
                </button>
              )}
              {j.status !== 'running' && j.status !== 'pending' && (
                <button
                  onClick={() => removeJob(j.id)}
                  disabled={deleting === j.id}
                  style={styles.removeBtn}
                  title="Remove this job from the list"
                >
                  {deleting === j.id ? '…' : 'Remove'}
                </button>
              )}
            </div>

            {output?.jobId === j.id && (
              <>
                {/* Only show LIVE badge when job is actually still running */}
                {isOutputJobRunning && (
                  <div style={styles.liveBadge}>● Live — updating every 1.5s</div>
                )}
                {/* Terminal panel: dark bg with light text — readable in both themes */}
                <pre style={styles.pre}>{output.text}</pre>

                {output.runnerKey === 'web_gowitness' && screenshots.length > 0 && (
                  <div style={styles.screenshots}>
                    <h4 style={styles.screenshotsTitle}>Screenshots (gowitness)</h4>
                    <div style={styles.screenshotGrid}>
                      {screenshots.map((s, i) => (
                        <div key={i} style={styles.screenshotCard}>
                          <a
                            href={api.screenshots.url(projectId, s.filename)}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={styles.screenshotLink}
                            onClick={(e) => {
                              e.preventDefault()
                              setPreviewUrl(api.screenshots.url(projectId, s.filename))
                            }}
                          >
                            <img
                              src={api.screenshots.url(projectId, s.filename)}
                              alt={s.url}
                              style={styles.thumbnail}
                              loading="lazy"
                            />
                          </a>
                          <span style={styles.screenshotUrl} title={s.url}>{s.url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </li>
        ))}
      </ul>

      {previewUrl && (
        <div style={styles.modal} onClick={() => setPreviewUrl(null)}>
          <div style={styles.modalContent} onClick={(e) => e.stopPropagation()}>
            <button style={styles.modalClose} onClick={() => setPreviewUrl(null)}>×</button>
            <img src={previewUrl} alt="Screenshot" style={styles.modalImg} />
          </div>
        </div>
      )}
    </div>
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusColor(s) {
  if (s === 'completed') return 'var(--primary)'
  if (s === 'failed')    return 'var(--danger)'
  if (s === 'running' || s === 'pending') return 'var(--warn)'
  return 'var(--text-muted)'
}

function dotColor(s) {
  if (s === 'running')   return '#34d399'
  if (s === 'completed') return '#34d399'
  if (s === 'failed')    return '#f87171'
  if (s === 'pending')   return '#fbbf24'
  return '#94a3b8'
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = {
  wrapper:    { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1rem' },
  list:       { listStyle: 'none', margin: 0, padding: 0 },
  item:       { padding: '0.5rem 0', borderTop: '1px solid var(--border)' },
  row:        { display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' },
  dot:        { width: 9, height: 9, borderRadius: '50%', flexShrink: 0 },
  runner:     { fontFamily: 'var(--font-mono)', fontWeight: 500, fontSize: '0.875rem' },
  status:     { textTransform: 'capitalize', fontSize: '0.85rem' },
  time:       { color: 'var(--text-muted)', fontSize: '0.8rem' },
  btn:        { marginLeft: 'auto', background: 'var(--surface)', color: 'var(--accent)', border: '1px solid var(--border)', fontSize: '0.85rem' },
  stopBtn:    { background: 'transparent', color: 'var(--danger)', border: '1px solid var(--danger)', fontSize: '0.85rem' },
  removeBtn:  { background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)', fontSize: '0.85rem' },
  cleanupRow: { marginBottom: '0.75rem' },
  cleanupBtn: { background: 'var(--surface)', color: 'var(--text-muted)', border: '1px solid var(--border)', fontSize: '0.9rem' },
  liveBadge:  { fontSize: '0.78rem', color: '#34d399', marginTop: '0.4rem', fontFamily: 'var(--font-mono)' },

  // Terminal — hardcoded dark bg + light text so it's readable in BOTH light and dark themes
  pre: {
    marginTop: '0.5rem',
    padding: '0.85rem 1rem',
    background: '#0d1117',
    color: '#e6edf3',
    borderRadius: 'var(--radius)',
    fontSize: '0.76rem',
    lineHeight: 1.65,
    fontFamily: 'var(--font-mono)',
    overflow: 'auto',
    maxHeight: 420,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    border: '1px solid #30363d',
  },

  empty:          { color: 'var(--text-muted)' },
  screenshots:    { marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border)' },
  screenshotsTitle: { margin: '0 0 0.5rem 0', fontSize: '0.95rem', fontWeight: 600 },
  screenshotGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem' },
  screenshotCard: { display: 'flex', flexDirection: 'column', gap: '0.25rem' },
  screenshotLink: { display: 'block', cursor: 'pointer' },
  thumbnail:      { width: '100%', maxHeight: 150, objectFit: 'cover', borderRadius: 'var(--radius)', border: '1px solid var(--border)' },
  screenshotUrl:  { fontSize: '0.75rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  modal:          { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '2rem' },
  modalContent:   { position: 'relative', maxWidth: '95vw', maxHeight: '95vh' },
  modalClose:     { position: 'absolute', top: -36, right: 0, background: 'var(--surface)', color: 'var(--text)', border: 'none', fontSize: '1.5rem', width: 36, height: 36, borderRadius: 'var(--radius)', cursor: 'pointer' },
  modalImg:       { maxWidth: '95vw', maxHeight: '95vh', objectFit: 'contain', borderRadius: 'var(--radius)' },
}
