import { useState, useEffect, useRef, useCallback, memo } from 'react'
import { api } from '../../api'

const POLL_INTERVAL_MS = 1500
const RETRY_LIMIT = 3

/**
 * JobCard
 *
 * Self-contained job card with isolated output polling.
 * Uses the app's existing CSS variables (--bg, --text, --surface, etc.)
 * so terminal output is readable in both light and dark modes.
 */
function JobCard({ job, projectId, onStop, onRemove, defaultExpanded = false }) {
  const [expanded,   setExpanded]   = useState(defaultExpanded)
  const [outputText, setOutputText] = useState('')
  const [isStopping, setIsStopping] = useState(false)
  const pollRef  = useRef(null)
  const retryRef = useRef(0)
  const preRef   = useRef(null)
  const userScrolledRef = useRef(false)

  const isRunning = job.status === 'running' || job.status === 'pending'

  // Auto-scroll pre to bottom when live and user hasn't scrolled up
  useEffect(() => {
    if (!isRunning || !expanded || userScrolledRef.current) return
    const el = preRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [outputText, isRunning, expanded])

  const fetchOutput = useCallback(async () => {
    try {
      const text = await api.jobs.output(projectId, job.id, 500)
      setOutputText(text || '')
      retryRef.current = 0
    } catch (err) {
      if (err?.status === 404) {
        setOutputText('(Output file not found.)')
        stopPolling()
      } else {
        retryRef.current += 1
        if (retryRef.current >= RETRY_LIMIT) {
          setOutputText(prev => prev + '\n\n[Polling failed — check backend connection.]')
          stopPolling()
        }
      }
    }
  }, [projectId, job.id]) // eslint-disable-line react-hooks/exhaustive-deps

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }, [])

  const startPolling = useCallback(() => {
    if (pollRef.current) return
    fetchOutput()
    pollRef.current = setInterval(fetchOutput, POLL_INTERVAL_MS)
  }, [fetchOutput])

  useEffect(() => {
    if (expanded && isRunning) {
      startPolling()
    } else if (expanded && !isRunning) {
      fetchOutput()
      stopPolling()
    } else {
      stopPolling()
    }
    return stopPolling
  }, [expanded, isRunning]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => () => stopPolling(), [stopPolling])

  const handleStop = async () => {
    if (isStopping) return
    setIsStopping(true)
    try { await onStop(job.id) } finally { setIsStopping(false) }
  }

  return (
    <div style={S.card}>
      {/* Header */}
      <div
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={() => setExpanded(e => !e)}
        onKeyDown={ev => { if (ev.key === 'Enter' || ev.key === ' ') setExpanded(e => !e) }}
        style={S.header}
      >
        <span style={{ ...S.dot, ...dotStyle(job.status) }} title={job.status} />
        <span style={S.runnerKey}>{job.runner_key}</span>
        <span style={{ ...S.statusLabel, color: statusColor(job.status) }}>{job.status}</span>
        {job.started_at && (
          <span style={S.timestamps}>
            {fmtTime(job.started_at)}
            {' · '}{fmtDuration(job.started_at, job.finished_at)}
          </span>
        )}
        <span style={{ flex: 1 }} />

        {/* Actions — stop clicks here not on the collapsible row */}
        <div style={S.actions} onClick={e => e.stopPropagation()}>
          {isRunning && (
            <button
              type="button"
              disabled={isStopping}
              onClick={handleStop}
              aria-label={`Stop ${job.runner_key}`}
              style={S.stopBtn}
            >
              {isStopping ? 'Stopping…' : 'Stop'}
            </button>
          )}
          {!isRunning && (
            <button
              type="button"
              onClick={() => onRemove(job.id)}
              aria-label={`Remove ${job.runner_key}`}
              style={S.removeBtn}
            >
              Remove
            </button>
          )}
        </div>

        <span style={{ ...S.chevron, transform: expanded ? 'rotate(180deg)' : 'none' }}>▾</span>
      </div>

      {/* Output panel */}
      {expanded && (
        <div>
          <div style={S.separator} />
          <div style={S.terminalWrap}>
            {isRunning && <span style={S.liveBadge}>● LIVE</span>}
            <button
              type="button"
              style={S.copyBtn}
              title="Copy output"
              onClick={() => navigator.clipboard?.writeText(outputText).catch(() => {})}
            >
              ⎘
            </button>
            <pre
              ref={preRef}
              style={S.pre}
              onScroll={e => {
                const el = e.currentTarget
                const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30
                userScrolledRef.current = !nearBottom
              }}
            >
              {outputText || '(No output yet.)'}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}

export default memo(JobCard)

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusColor(s) {
  switch (s) {
    case 'running':   return 'var(--primary)'
    case 'completed': return 'var(--primary)'
    case 'failed':    return 'var(--danger)'
    case 'stopped':   return 'var(--text-muted)'
    case 'pending':   return 'var(--warn)'
    default:          return 'var(--text-muted)'
  }
}

function dotStyle(s) {
  const base = { background: statusColor(s) }
  if (s === 'running') return { ...base, boxShadow: '0 0 0 3px rgba(52,211,153,0.2)', animation: 'noneY' }
  return base
}

function fmtTime(iso) {
  if (!iso) return ''
  try { return new Date(iso).toLocaleTimeString() } catch { return iso }
}

function fmtDuration(start, end) {
  if (!start) return ''
  const diff = Math.round((new Date(end || Date.now()) - new Date(start)) / 1000)
  if (diff < 60) return `${diff}s`
  const m = Math.floor(diff / 60), sec = diff % 60
  return sec > 0 ? `${m}m ${sec}s` : `${m}m`
}

// ── Styles ────────────────────────────────────────────────────────────────────
// Uses ONLY existing app CSS variables (--bg, --surface, --text, --border, etc.)
// so output is readable in both light and dark mode without requiring globals.css.

const S = {
  card: {
    width: '100%',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    marginBottom: 8,
    overflow: 'hidden',
  },
  header: {
    display: 'flex', alignItems: 'center', gap: 10,
    padding: '10px 14px', cursor: 'pointer', userSelect: 'none',
  },
  dot: { width: 10, height: 10, borderRadius: '50%', flexShrink: 0 },
  runnerKey: { fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text)', flexShrink: 0 },
  statusLabel: { fontSize: '0.75rem', flexShrink: 0 },
  timestamps: { fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 },
  actions: { display: 'flex', gap: 6, flexShrink: 0 },
  stopBtn: { fontSize: '0.75rem', padding: '2px 10px', borderRadius: 'var(--radius-sm)', cursor: 'pointer', background: 'transparent', border: '1px solid var(--danger)', color: 'var(--danger)' },
  removeBtn: { fontSize: '0.75rem', padding: '2px 10px', borderRadius: 'var(--radius-sm)', cursor: 'pointer', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)' },
  chevron: { fontSize: '1rem', color: 'var(--text-muted)', transition: 'transform 0.15s', flexShrink: 0 },
  separator: { height: 1, background: 'var(--border)' },

  // Terminal — dark panel that reads well in both themes
  terminalWrap: {
    position: 'relative',
    background: '#0d1117',  // hard dark — intentional, readable in both themes
    borderTop: '1px solid var(--border)',
  },
  liveBadge: {
    position: 'absolute', top: 8, right: 40,
    fontFamily: 'var(--font-mono)', fontSize: '0.68rem',
    color: '#3fb950',
    pointerEvents: 'none',
    zIndex: 2,
    animation: 'livePulse 1.5s ease-in-out infinite',
  },
  copyBtn: {
    position: 'absolute', top: 6, right: 8,
    width: 26, height: 26, display: 'flex', alignItems: 'center', justifyContent: 'center',
    background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.12)',
    borderRadius: 4, color: '#8b949e', cursor: 'pointer', fontSize: '0.85rem', zIndex: 2,
  },
  pre: {
    margin: 0, padding: '12px 14px',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.75rem',
    lineHeight: 1.65,
    color: '#e6edf3',        // light text on dark background — always readable
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    maxHeight: 500,
    overflowY: 'auto',
    background: 'transparent',
  },
}

// Inject keyframe once
if (typeof document !== 'undefined' && !document.getElementById('jobcard-kf')) {
  const style = document.createElement('style')
  style.id = 'jobcard-kf'
  style.textContent = `
    @keyframes livePulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
  `
  document.head.appendChild(style)
}
