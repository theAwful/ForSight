import { useState, useEffect, useRef, useCallback, memo } from 'react'
import { api } from '../../api'
import TerminalPanel from '../ui/TerminalPanel'

const POLL_INTERVAL_MS = 1500
const RETRY_LIMIT = 3

/**
 * JobCard
 *
 * Displays a single scan job with expandable live terminal output.
 * Output state is self-contained here — does not cause sibling re-renders.
 * Polling starts only when the card is expanded and the job is running.
 *
 * Props:
 *   job            ScanJob object
 *   projectId      number
 *   onStop         (jobId) => void
 *   onRemove       (jobId) => void
 *   defaultExpanded boolean (default false)
 */
function JobCard({ job, projectId, onStop, onRemove, defaultExpanded = false }) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const [outputText, setOutputText] = useState('')
  const [isStopping, setIsStopping] = useState(false)
  const pollRef = useRef(null)
  const retryRef = useRef(0)

  const isRunning = job.status === 'running' || job.status === 'pending'

  const fetchOutput = useCallback(async () => {
    try {
      const text = await api.jobs.output(projectId, job.id, 1000)
      setOutputText(text || '')
      retryRef.current = 0
    } catch (err) {
      if (err?.status === 404) {
        setOutputText('(Output file not found. The job may have been cleaned up.)')
        stopPolling()
      } else {
        retryRef.current += 1
        if (retryRef.current >= RETRY_LIMIT) {
          setOutputText((prev) => prev + '\n\n[Output polling failed. Check backend connection.]')
          stopPolling()
        }
      }
    }
  }, [projectId, job.id])

  const startPolling = useCallback(() => {
    if (pollRef.current) return
    fetchOutput()
    pollRef.current = setInterval(fetchOutput, POLL_INTERVAL_MS)
  }, [fetchOutput])

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [])

  // Start/stop polling based on expand state and job status
  useEffect(() => {
    if (expanded && isRunning) {
      startPolling()
    } else if (expanded && !isRunning) {
      // Job just completed while expanded — do one final fetch
      fetchOutput()
      stopPolling()
    } else {
      stopPolling()
    }
    return stopPolling
  }, [expanded, isRunning, startPolling, stopPolling, fetchOutput])

  // If not running and expanded but no output yet, fetch once on mount
  useEffect(() => {
    if (expanded && !isRunning && !outputText) {
      fetchOutput()
    }
  }, [expanded]) // eslint-disable-line react-hooks/exhaustive-deps

  // Cleanup on unmount
  useEffect(() => () => stopPolling(), [stopPolling])

  const handleStop = async () => {
    if (isStopping) return
    setIsStopping(true)
    try {
      await onStop(job.id)
    } finally {
      setIsStopping(false)
    }
  }

  const duration = formatDuration(job.started_at, job.finished_at)

  return (
    <div style={styles.card}>
      {/* Header row — click to expand */}
      <div
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-label={`${job.runner_key} — ${job.status}`}
        onClick={() => setExpanded((e) => !e)}
        onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') setExpanded((e) => !e) }}
        style={styles.header}
      >
        {/* Status dot */}
        <span style={{ ...styles.dot, ...dotStyle(job.status) }} title={job.status} />

        {/* Runner name */}
        <span style={styles.runnerKey}>{job.runner_key}</span>

        {/* Status label */}
        <span style={{ ...styles.statusLabel, color: statusColor(job.status) }}>{job.status}</span>

        {/* Timestamps */}
        {job.started_at && (
          <span style={styles.timestamps}>
            {formatTime(job.started_at)}
            {duration && <> · {duration}</>}
          </span>
        )}

        {/* Spacer */}
        <span style={{ flex: 1 }} />

        {/* Actions */}
        <div
          style={styles.actions}
          onClick={(e) => e.stopPropagation()}
        >
          {isRunning && (
            <button
              type="button"
              onClick={handleStop}
              disabled={isStopping}
              aria-label={`Stop job ${job.runner_key}`}
              style={{ ...styles.actionBtn, ...styles.stopBtn, ...(isStopping ? styles.disabledBtn : {}) }}
            >
              {isStopping ? 'Stopping…' : 'Stop'}
            </button>
          )}
          {!isRunning && (
            <button
              type="button"
              onClick={() => onRemove(job.id)}
              aria-label={`Remove job ${job.runner_key}`}
              style={{ ...styles.actionBtn, ...styles.removeBtn }}
            >
              Remove
            </button>
          )}
        </div>

        {/* Chevron */}
        <span style={{ ...styles.chevron, transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)' }}>
          ▾
        </span>
      </div>

      {/* Output panel */}
      {expanded && (
        <div style={styles.outputWrap}>
          <div style={styles.separator} />
          <TerminalPanel
            text={outputText}
            isLive={isRunning}
          />
        </div>
      )}
    </div>
  )
}

// Memoize so sibling JobCards don't re-render when one job's output changes
export default memo(JobCard)

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTime(iso) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleTimeString()
  } catch {
    return iso
  }
}

function formatDuration(start, end) {
  if (!start) return ''
  const s = new Date(start)
  const e = end ? new Date(end) : new Date()
  const diff = Math.round((e - s) / 1000)
  if (diff < 60) return `${diff}s`
  const m = Math.floor(diff / 60)
  const sec = diff % 60
  return sec > 0 ? `${m}m ${sec}s` : `${m}m`
}

function statusColor(status) {
  switch (status) {
    case 'running':   return 'var(--color-success)'
    case 'completed': return 'var(--color-success)'
    case 'failed':    return 'var(--color-danger)'
    case 'stopped':   return 'var(--color-text-disabled)'
    case 'pending':   return 'var(--color-warning)'
    default:          return 'var(--color-text-secondary)'
  }
}

function dotStyle(status) {
  const base = { background: statusColor(status) }
  if (status === 'running') {
    return {
      ...base,
      boxShadow: '0 0 0 3px rgba(63,185,80,0.25)',
      animation: 'live-pulse 1.5s ease-in-out infinite',
    }
  }
  return base
}

// ── Styles ───────────────────────────────────────────────────────────────────

const styles = {
  card: {
    width: '100%',
    background: 'var(--color-bg-surface)',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-md)',
    marginBottom: '10px',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '10px 14px',
    cursor: 'pointer',
    userSelect: 'none',
    transition: 'background 0.1s',
  },
  dot: {
    width: '10px',
    height: '10px',
    borderRadius: '50%',
    flexShrink: 0,
  },
  runnerKey: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.85rem',
    fontWeight: 600,
    color: 'var(--color-text-primary)',
    flexShrink: 0,
  },
  statusLabel: {
    fontSize: '0.75rem',
    flexShrink: 0,
  },
  timestamps: {
    fontSize: '0.72rem',
    color: 'var(--color-text-disabled)',
    fontFamily: 'var(--font-mono)',
    flexShrink: 0,
  },
  actions: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    flexShrink: 0,
  },
  actionBtn: {
    fontSize: '0.75rem',
    padding: '2px 10px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
    background: 'transparent',
    transition: 'background 0.1s, border-color 0.1s',
  },
  stopBtn: {
    border: '1px solid var(--color-danger)',
    color: 'var(--color-danger)',
  },
  removeBtn: {
    border: '1px solid var(--color-border)',
    color: 'var(--color-text-secondary)',
  },
  disabledBtn: {
    opacity: 0.5,
    cursor: 'not-allowed',
    pointerEvents: 'none',
  },
  chevron: {
    fontSize: '1rem',
    color: 'var(--color-text-secondary)',
    transition: 'transform 0.15s ease',
    flexShrink: 0,
  },
  separator: {
    height: '1px',
    background: 'var(--color-border)',
  },
  outputWrap: {},
}
