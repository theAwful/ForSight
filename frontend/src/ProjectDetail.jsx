import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { api } from './api'
import Checklist from './Checklist'
import Jobs from './Jobs'
import Logs from './Logs'
import Hosts from './Hosts'
import ConfirmModal from './ConfirmModal'

const PHASE_LABELS = {
  pre_engagement: 'Pre-engagement',
  recon: 'Recon',
  enumeration: 'Enumeration',
  web_host: 'Web host',
  exploitation: 'Exploitation',
  reporting: 'Reporting',
}

export default function ProjectDetail() {
  const { projectId } = useParams()
  const [project, setProject] = useState(null)
  const [checklist, setChecklist] = useState([])
  const [jobs, setJobs] = useState([])
  const [tab, setTab] = useState('checklist')
  const [roeFile, setRoeFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [pasteText, setPasteText] = useState('')
  const [pasting, setPasting] = useState(false)
  const [loadError, setLoadError] = useState(null)
  const [nmapDone, setNmapDone] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [targets, setTargets] = useState({ ips: [], domains: [] })
  const [editingTargets, setEditingTargets] = useState(false)
  const [editTargetsText, setEditTargetsText] = useState('')
  const [savingTargets, setSavingTargets] = useState(false)
  const navigate = useNavigate()

  const load = () => {
    if (!projectId) return
    setLoadError(null)
    api.projects
      .get(projectId)
      .then((p) => {
        setProject(p != null && typeof p === 'object' ? p : null)
        setLoadError(null)
      })
      .catch((err) => {
        setProject(null)
        setLoadError(err?.message || 'Failed to load project')
        if (err?.status === 404) navigate('/', { replace: true })
      })
    api.checklist
      .project(projectId)
      .then((data) => setChecklist(Array.isArray(data) ? data : []))
      .catch((err) => {
        setChecklist([])
        if (err?.status === 404) navigate('/', { replace: true })
      })
    api.jobs
      .list(projectId)
      .then((data) => setJobs(Array.isArray(data) ? data : []))
      .catch(() => setJobs([]))
    api.projects
      .nmapReady(projectId)
      .then((r) => setNmapDone(r?.nmap_done === true))
      .catch(() => setNmapDone(false))
    api.projects
      .targets(projectId)
      .then((t) => setTargets({ ips: t?.ips ?? [], domains: t?.domains ?? [] }))
      .catch(() => setTargets({ ips: [], domains: [] }))
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 3000)
    return () => clearInterval(t)
  }, [projectId])

  const onRoeUpload = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    try {
      await api.projects.uploadRoe(projectId, file)
      load()
      setRoeFile(null)
    } finally {
      setUploading(false)
    }
  }

  const onPasteRoe = async () => {
    if (!pasteText.trim()) return
    setPasting(true)
    try {
      await api.projects.pasteRoe(projectId, pasteText.trim())
      load()
      setPasteText('')
    } finally {
      setPasting(false)
    }
  }

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const onDeleteProject = () => setShowDeleteConfirm(true)

  const startEditTargets = () => {
    const lines = [...(targets.ips || []), ...(targets.domains || [])]
    setEditTargetsText(lines.join('\n'))
    setEditingTargets(true)
  }

  const saveTargets = async () => {
    setSavingTargets(true)
    try {
      await api.projects.updateTargets(projectId, editTargetsText)
      setEditingTargets(false)
      load()
    } catch (err) {
      window.alert(err?.body?.detail || err?.message || 'Failed to save targets')
    } finally {
      setSavingTargets(false)
    }
  }

  const cancelEditTargets = () => {
    setEditingTargets(false)
    setEditTargetsText('')
  }

  const confirmDeleteProject = async () => {
    if (!project?.name) return
    setDeleting(true)
    try {
      await api.projects.delete(projectId)
      setShowDeleteConfirm(false)
      navigate('/')
    } catch (err) {
      window.alert(err?.body?.detail || err?.message || 'Failed to delete project')
    } finally {
      setDeleting(false)
    }
  }

  if (!projectId) {
    return (
      <div style={styles.msg}>
        Invalid project. <Link to="/" style={styles.link}>Back to engagements</Link>
      </div>
    )
  }
  if (loadError) {
    return (
      <div style={styles.msg}>
        <strong>{loadError}</strong>
        <br />
        <Link to="/" style={styles.link}>Back to engagements</Link>
      </div>
    )
  }
  if (!project) {
    return <div style={{ color: 'var(--text-muted)' }}>Loading…</div>
  }

  return (
    <div>
      <div style={styles.header}>
        <div>
          <h1 style={styles.title}>{project?.name ?? 'Project'}</h1>
          {project?.targets_summary && (
            <span style={styles.summary}>
              {project.targets_summary.ips} IPs, {project.targets_summary.domains} domains
              {project.roe_filename && ` · ${project.roe_filename}`}
            </span>
          )}
        </div>
        <button
          type="button"
          className="btn-secondary"
          style={styles.deleteProjectBtn}
          onClick={onDeleteProject}
          disabled={deleting}
          title="Delete this project"
        >
          {deleting ? 'Deleting…' : 'Delete project'}
        </button>
      </div>

      <div style={styles.roe}>
        <label style={styles.roeLabel}>
          <span>Upload ROE (IPs / domains):</span>
          <input
            type="file"
            accept=".txt,.csv,.json"
            onChange={onRoeUpload}
            disabled={uploading}
            style={styles.fileInput}
          />
          <span style={styles.roeBtn}>{uploading ? 'Uploading…' : 'Choose file'}</span>
        </label>
        <div style={styles.pasteRow}>
          <textarea
            placeholder="Or paste IPs/domains (one per line)."
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            style={styles.pasteInput}
            rows={3}
          />
          <button onClick={onPasteRoe} disabled={pasting || !pasteText.trim()} style={styles.pasteBtn}>
            {pasting ? 'Saving…' : 'Save as ROE'}
          </button>
        </div>
      </div>

      <div style={styles.mainRow}>
        <div style={styles.tabContentArea}>
          <div className="tabs-row" style={styles.tabs}>
            {['checklist', 'jobs', 'hosts', 'reporting'].map((t) => (
              <button
                key={t}
                type="button"
                className={`tab-btn ${tab === t ? 'tab-btn-active' : ''}`}
                onClick={() => setTab(t)}
                style={{ ...styles.tab, ...(tab === t ? styles.tabActive : {}) }}
              >
                {t === 'checklist' ? 'Checklist' : t === 'jobs' ? 'Jobs' : t === 'hosts' ? 'Hosts' : 'Reporting'}
              </button>
            ))}
          </div>

          <div key={tab} className="tab-content main-content" style={{ minHeight: 200 }}>
            {tab === 'checklist' && (
              <Checklist
                projectId={projectId}
                checklist={checklist}
                onRun={load}
                onStatusChange={load}
                nmapDone={nmapDone}
              />
            )}
            {tab === 'jobs' && (
              <Jobs projectId={projectId} jobs={jobs} onRefresh={load} />
            )}
            {tab === 'logs' && (
              <Logs projectId={projectId} jobs={jobs} onRefresh={load} />
            )}
            {tab === 'hosts' && <Hosts projectId={projectId} onRefresh={load} />}
            {tab === 'reporting' && (
              <div className="card" style={styles.reportingCard}>
                <h2 style={styles.reportingTitle}>Reporting & wrap-up</h2>
                <p style={styles.reportingLead}>Download all tool outputs (workpapers) as a zip for this project.</p>
                <a
                  href={api.projects.downloadOutputsUrl(projectId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-primary"
                  style={styles.downloadBtn}
                >
                  Download workpapers (zip)
                </a>
              </div>
            )}
          </div>
        </div>

        <div className="card" style={styles.targetsPanel}>
          <h3 style={styles.targetsTitle}>Current targets</h3>
          {editingTargets ? (
            <div style={styles.targetsEditor}>
              <textarea
                value={editTargetsText}
                onChange={(e) => setEditTargetsText(e.target.value)}
                placeholder="One IP or domain per line"
                style={styles.targetsTextarea}
                rows={12}
              />
              <div style={styles.targetsEditorActions}>
                <button type="button" className="btn-secondary" onClick={cancelEditTargets} style={styles.targetsBtn}>
                  Cancel
                </button>
                <button type="button" className="btn-primary" onClick={saveTargets} disabled={savingTargets} style={styles.targetsBtn}>
                  {savingTargets ? 'Saving…' : 'Save'}
                </button>
              </div>
            </div>
          ) : (
            <>
              <div style={styles.targetsScroll}>
                {((targets.ips || []).length + (targets.domains || []).length) === 0 ? (
                  <p style={styles.targetsEmpty}>No targets. Upload ROE or paste above.</p>
                ) : (
                  <ul style={styles.targetsList}>
                    {(targets.ips || []).map((ip, i) => (
                      <li key={`ip-${i}`} style={styles.targetsItem}>{ip}</li>
                    ))}
                    {(targets.domains || []).map((d, i) => (
                      <li key={`dom-${i}`} style={styles.targetsItem}>{d}</li>
                    ))}
                  </ul>
                )}
              </div>
              <button type="button" className="btn-secondary" onClick={startEditTargets} style={styles.editTargetsBtn}>
                Edit targets
              </button>
            </>
          )}
        </div>
      </div>
      <ConfirmModal
        open={showDeleteConfirm}
        title="Delete project?"
        message={project ? `"${project.name}" will be permanently removed. This cannot be undone.` : ''}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        danger
        loading={deleting}
        onConfirm={confirmDeleteProject}
        onCancel={() => setShowDeleteConfirm(false)}
      />
    </div>
  )
}

const styles = {
  msg: { color: 'var(--text-muted)', marginBottom: '1rem' },
  link: { color: 'var(--accent)', marginTop: '0.5rem', display: 'inline-block' },
  header: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem', marginBottom: '1rem', flexWrap: 'wrap' },
  title: { margin: 0, fontSize: '1.5rem', fontWeight: 600 },
  summary: { color: 'var(--text-muted)', fontSize: '0.9rem', display: 'block', marginTop: '0.25rem' },
  deleteProjectBtn: { color: 'var(--danger)', borderColor: 'var(--danger)' },
  roe: { marginBottom: '1.5rem' },
  roeLabel: { display: 'inline-flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' },
  fileInput: { width: 0, height: 0, opacity: 0, position: 'absolute' },
  roeBtn: {
    padding: '0.5rem 1rem',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    cursor: 'pointer',
  },
  pasteRow: { marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', maxWidth: 500 },
  pasteInput: { padding: '0.5rem', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '0.9rem' },
  pasteBtn: { alignSelf: 'flex-start', background: 'var(--accent)', color: 'var(--accent-text)' },
  mainRow: { display: 'flex', gap: '1.5rem', alignItems: 'flex-start' },
  tabContentArea: { flex: 1, minWidth: 0 },
  tabs: { display: 'flex', gap: '0.25rem', marginBottom: '1rem' },
  tab: { background: 'transparent', color: 'var(--text-muted)', padding: '0.5rem 1rem', borderRadius: 'var(--radius)', transition: 'background-color 0.15s ease, color 0.15s ease' },
  tabActive: { color: 'var(--accent)', background: 'var(--surface)', border: '1px solid var(--border)' },
  targetsPanel: { flexShrink: 0, width: 280, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '0.75rem', display: 'flex', flexDirection: 'column' },
  targetsTitle: { margin: '0 0 0.5rem 0', fontSize: '0.9rem', fontWeight: 600 },
  targetsScroll: { flex: 1, minHeight: 120, maxHeight: 320, overflowY: 'auto', marginBottom: '0.5rem', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '0.5rem', background: 'var(--bg)' },
  targetsList: { listStyle: 'none', margin: 0, padding: 0, fontFamily: 'var(--font-mono)', fontSize: '0.8rem' },
  targetsItem: { padding: '0.2rem 0', borderBottom: '1px solid var(--border)', wordBreak: 'break-all' },
  targetsEmpty: { margin: 0, color: 'var(--text-muted)', fontSize: '0.85rem' },
  editTargetsBtn: { width: '100%' },
  targetsEditor: { display: 'flex', flexDirection: 'column', gap: '0.5rem' },
  targetsTextarea: { padding: '0.5rem', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', minHeight: 200 },
  targetsEditorActions: { display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' },
  targetsBtn: { padding: '0.35rem 0.75rem' },
  reportingCard: { padding: '1.5rem', maxWidth: 480 },
  reportingTitle: { margin: '0 0 0.5rem 0', fontSize: '1.25rem', fontWeight: 600 },
  reportingLead: { margin: '0 0 1rem 0', color: 'var(--text-muted)', lineHeight: 1.5 },
  downloadBtn: { display: 'inline-block', padding: '0.5rem 1rem', textDecoration: 'none' },
}
