import { useState, useCallback, memo } from 'react'
import { api } from '../api'
import JobCard from '../components/jobs/JobCard'
import { useToast } from '../components/ui/Toast'

/**
 * Jobs tab — lists all scan jobs for a project.
 * Each JobCard is memoized and manages its own output polling,
 * so live output updates for one job don't re-render siblings.
 */
export default function Jobs({ projectId, jobs, onRefresh }) {
  const { toast } = useToast()
  const [stoppingId, setStoppingId] = useState(null)

  const handleStop = useCallback(async (jobId) => {
    setStoppingId(jobId)
    try {
      await api.jobs.stop(projectId, jobId)
      onRefresh()
    } catch (err) {
      toast.error(`Failed to stop job: ${err?.message || 'Unknown error'}`)
    } finally {
      setStoppingId(null)
    }
  }, [projectId, onRefresh, toast])

  const handleRemove = useCallback(async (jobId) => {
    try {
      await api.jobs.delete(projectId, jobId)
      onRefresh()
    } catch (err) {
      toast.error(`Failed to remove job: ${err?.message || 'Unknown error'}`)
    }
  }, [projectId, onRefresh, toast])

  if (!jobs?.length) {
    return (
      <div style={styles.empty}>
        <span style={styles.emptyIcon}>⚡</span>
        <p style={styles.emptyText}>No jobs yet. Run a checklist item to see output here.</p>
      </div>
    )
  }

  // Sort newest first
  const sorted = [...jobs].sort((a, b) => {
    const ta = a.started_at ? new Date(a.started_at).getTime() : 0
    const tb = b.started_at ? new Date(b.started_at).getTime() : 0
    return tb - ta
  })

  // Auto-expand the most recent running job
  const latestRunningId = sorted.find((j) => j.status === 'running')?.id

  return (
    <div style={styles.wrapper}>
      <div style={styles.header}>
        <span style={styles.count}>{jobs.length} job{jobs.length !== 1 ? 's' : ''}</span>
        <button type="button" onClick={onRefresh} style={styles.refreshBtn} aria-label="Refresh job list">
          ↻ Refresh
        </button>
      </div>

      <div style={styles.list}>
        {sorted.map((job) => (
          <JobCard
            key={job.id}
            job={job}
            projectId={projectId}
            onStop={handleStop}
            onRemove={handleRemove}
            defaultExpanded={job.id === latestRunningId}
          />
        ))}
      </div>
    </div>
  )
}

const styles = {
  wrapper: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '14px',
  },
  count: {
    fontSize: '0.82rem',
    color: 'var(--color-text-secondary)',
  },
  refreshBtn: {
    background: 'none',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--color-text-secondary)',
    fontSize: '0.78rem',
    padding: '3px 10px',
    cursor: 'pointer',
  },
  list: {
    display: 'flex',
    flexDirection: 'column',
  },
  empty: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    padding: '48px 24px',
    gap: '12px',
    color: 'var(--color-text-secondary)',
  },
  emptyIcon: {
    fontSize: '2rem',
    opacity: 0.5,
  },
  emptyText: {
    margin: 0,
    fontSize: '0.875rem',
  },
}
