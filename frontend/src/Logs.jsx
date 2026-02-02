import { useState, useEffect } from 'react'
import { api } from './api'

/** Dedicated tab for viewing job logs (output only). */
export default function Logs({ projectId, jobs, onRefresh }) {
  const [expandedId, setExpandedId] = useState(null)
  const [logText, setLogText] = useState('')
  const [loadingId, setLoadingId] = useState(null)

  useEffect(() => {
    if (!expandedId || !projectId) return
    setLoadingId(expandedId)
    api.jobs
      .output(projectId, expandedId)
      .then(setLogText)
      .catch(() => setLogText('(Failed to load log)'))
      .finally(() => setLoadingId(null))
  }, [projectId, expandedId])

  useEffect(() => {
    if (!expandedId) return
    const job = jobs?.find((j) => j.id === expandedId)
    if (job && (job.status === 'running' || job.status === 'pending')) {
      const t = setInterval(() => {
        api.jobs.output(projectId, expandedId).then(setLogText).catch(() => {})
      }, 2000)
      return () => clearInterval(t)
    }
  }, [projectId, expandedId, jobs])

  if (!jobs?.length) return <div style={styles.empty}>No jobs yet. Run a checklist item to see logs here.</div>

  return (
    <div style={styles.wrapper}>
      <p style={styles.hint}>Click a job to view its log output. Live jobs refresh every 2s.</p>
      <ul style={styles.list}>
        {jobs.map((j) => {
          const open = expandedId === j.id
          return (
            <li key={j.id} style={styles.item}>
              <button
                style={styles.row}
                onClick={() => setExpandedId(open ? null : j.id)}
                aria-expanded={open}
              >
                <span style={styles.runner}>{j.runner_key}</span>
                <span style={{ ...styles.status, ...statusColor(j.status) }}>{j.status}</span>
                <span style={styles.time}>
                  {j.started_at ? new Date(j.started_at).toLocaleString() : '—'}
                </span>
                <span style={styles.chevron}>{open ? '▼' : '▶'}</span>
              </button>
              {open && (
                <div style={styles.logWrap}>
                  {loadingId === j.id ? (
                    <div style={styles.loading}>Loading…</div>
                  ) : (
                    <pre style={styles.pre} className="font-mono pre-wrap">
                      {logText || '(No output yet)'}
                    </pre>
                  )}
                </div>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function statusColor(s) {
  if (s === 'completed') return { color: 'var(--accent)' }
  if (s === 'failed') return { color: 'var(--danger)' }
  if (s === 'running' || s === 'pending') return { color: 'var(--warn)' }
  return {}
}

const styles = {
  wrapper: { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1rem' },
  hint: { color: 'var(--text-muted)', fontSize: '0.9rem', margin: '0 0 0.75rem 0' },
  list: { listStyle: 'none', margin: 0, padding: 0 },
  item: { borderTop: '1px solid var(--border)' },
  row: { display: 'flex', alignItems: 'center', gap: '1rem', width: '100%', padding: '0.5rem 0', background: 'transparent', color: 'var(--text)', textAlign: 'left', cursor: 'pointer', fontSize: '0.9rem' },
  runner: { fontFamily: 'var(--font-mono)', fontWeight: 500 },
  status: { textTransform: 'capitalize' },
  time: { color: 'var(--text-muted)', fontSize: '0.85rem' },
  chevron: { marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)' },
  logWrap: { padding: '0.5rem 0 1rem 0', borderTop: '1px solid var(--border)' },
  loading: { color: 'var(--text-muted)', padding: '0.5rem 0' },
  pre: { margin: 0, padding: '0.75rem', background: 'var(--bg)', borderRadius: 'var(--radius)', fontSize: '0.8rem', overflow: 'auto', maxHeight: 360 },
  empty: { color: 'var(--text-muted)' },
}
