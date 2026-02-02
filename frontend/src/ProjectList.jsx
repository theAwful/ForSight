import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from './api'
import ConfirmModal from './ConfirmModal'

export default function ProjectList() {
  const [projects, setProjects] = useState([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState(null)
  const [deleteConfirm, setDeleteConfirm] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    api.projects.list().then(setProjects).finally(() => setLoading(false))
  }, [])

  const openDeleteConfirm = (e, p) => {
    e.preventDefault()
    e.stopPropagation()
    setDeleteConfirm(p)
  }

  const closeDeleteConfirm = () => setDeleteConfirm(null)

  const confirmDelete = async () => {
    if (!deleteConfirm) return
    const p = deleteConfirm
    setDeleting(p.id)
    try {
      await api.projects.delete(p.id)
      setProjects((prev) => prev.filter((x) => x.id !== p.id))
      setDeleteConfirm(null)
      navigate('/')
    } catch (err) {
      window.alert(err?.body?.detail || err?.message || 'Failed to delete project')
    } finally {
      setDeleting(null)
    }
  }

  const create = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    try {
      const p = await api.projects.create(name.trim())
      setProjects((prev) => [p, ...prev])
      setName('')
    } finally {
      setCreating(false)
    }
  }

  if (loading) return <div style={styles.loading}>Loading engagements…</div>

  return (
    <div style={styles.page}>
      <header style={styles.hero}>
        <h1 style={styles.title}>Engagements</h1>
        <p style={styles.subtitle}>Create and manage external pentest engagements. Upload an ROE (IPs & domains), then run the checklist.</p>
      </header>

      <section style={styles.createCard} className="card">
        <h2 style={styles.sectionTitle}>New engagement</h2>
        <form onSubmit={create} style={styles.form}>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Acme Corp Q1 2025"
            className="input-search"
            style={styles.input}
          />
          <button type="submit" disabled={creating} className="btn-primary" style={styles.createBtn}>
            {creating ? 'Creating…' : 'Create'}
          </button>
        </form>
      </section>

      <section style={styles.listSection}>
        <h2 style={styles.sectionTitle}>
          Your engagements
          {projects.length > 0 && <span style={styles.count}>{projects.length}</span>}
        </h2>
        {projects.length === 0 ? (
          <div style={styles.emptyCard} className="card">
            <p style={styles.emptyText}>No engagements yet.</p>
            <p style={styles.emptyHint}>Create one above, then open it to upload an ROE and run the checklist.</p>
          </div>
        ) : (
          <ul style={styles.list}>
            {projects.map((p) => (
              <li key={p.id} style={styles.listItem}>
                <Link to={`/projects/${p.id}`} style={styles.cardLink} className="card">
                  <span style={styles.cardAccent} aria-hidden />
                  <div style={styles.cardBody}>
                    <span style={styles.cardName}>{p.name}</span>
                    <div style={styles.cardMeta}>
                      {p.roe_filename && <span style={styles.metaItem}>ROE: {p.roe_filename}</span>}
                      {p.targets_summary && (
                        <span style={styles.metaItem}>
                          {p.targets_summary.ips} IPs, {p.targets_summary.domains} domains
                        </span>
                      )}
                    </div>
                  </div>
                  <span style={styles.cardArrow}>→</span>
                </Link>
                <button
                  type="button"
                  className="btn-secondary"
                  style={styles.deleteBtn}
                  onClick={(e) => openDeleteConfirm(e, p)}
                  disabled={deleting === p.id}
                  title="Delete engagement"
                >
                  {deleting === p.id ? 'Deleting…' : 'Delete'}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
      <ConfirmModal
        open={!!deleteConfirm}
        title="Delete project?"
        message={deleteConfirm ? `"${deleteConfirm.name}" will be permanently removed. This cannot be undone.` : ''}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        danger
        loading={deleting === deleteConfirm?.id}
        onConfirm={confirmDelete}
        onCancel={closeDeleteConfirm}
      />
    </div>
  )
}

const styles = {
  page: { maxWidth: 720, margin: '0 auto' },
  loading: { color: 'var(--text-muted)', padding: '2rem' },
  hero: { marginBottom: '2rem' },
  title: { margin: 0, fontSize: '1.75rem', fontWeight: 700, color: 'var(--text)', letterSpacing: '-0.02em' },
  subtitle: { margin: '0.5rem 0 0', fontSize: '0.95rem', color: 'var(--text-muted)', lineHeight: 1.5 },
  createCard: {
    padding: '1.25rem 1.5rem',
    marginBottom: '1.5rem',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    boxShadow: 'var(--shadow-sm)',
  },
  sectionTitle: { margin: 0, fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.04em', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' },
  count: { background: 'var(--border)', color: 'var(--text-muted)', fontSize: '0.75rem', padding: '0.15rem 0.5rem', borderRadius: 'var(--radius-sm)' },
  form: { display: 'flex', gap: '0.5rem', flexWrap: 'wrap' },
  input: {
    flex: 1,
    minWidth: 200,
    padding: '0.6rem 0.75rem',
    borderRadius: 'var(--radius)',
    border: '1px solid var(--border)',
    background: 'var(--bg)',
    color: 'var(--text)',
    fontSize: '1rem',
    fontFamily: 'var(--font-sans)',
  },
  createBtn: { padding: '0.6rem 1.25rem', background: 'var(--accent)', color: 'var(--accent-text)', fontWeight: 500 },
  listSection: { marginTop: '0.5rem' },
  list: { listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: '0.5rem' },
  listItem: { display: 'flex', alignItems: 'stretch', gap: '0.5rem' },
  cardLink: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    padding: 0,
    background: 'var(--surface)',
    borderRadius: 'var(--radius)',
    border: '1px solid var(--border)',
    color: 'var(--text)',
    textDecoration: 'none',
    overflow: 'hidden',
    transition: 'box-shadow 0.15s ease, border-color 0.15s ease',
    minWidth: 0,
  },
  cardAccent: { width: 4, flexShrink: 0, background: 'var(--accent)', alignSelf: 'stretch' },
  cardBody: { flex: 1, minWidth: 0, padding: '1rem 1rem 1rem 1.25rem' },
  cardName: { display: 'block', fontWeight: 600, fontSize: '1rem', color: 'var(--text)' },
  cardMeta: { display: 'flex', flexWrap: 'wrap', gap: '0.5rem 1rem', marginTop: '0.35rem', fontSize: '0.85rem', color: 'var(--text-muted)' },
  metaItem: {},
  cardArrow: { padding: '1rem 1rem 1rem 0', color: 'var(--text-muted)', fontSize: '1.25rem', flexShrink: 0 },
  deleteBtn: { flexShrink: 0, color: 'var(--danger)', borderColor: 'var(--danger)', alignSelf: 'center' },
  emptyCard: { padding: '2rem 1.5rem', textAlign: 'center', background: 'var(--surface)', border: '1px dashed var(--border)', borderRadius: 'var(--radius)' },
  emptyText: { margin: 0, fontWeight: 600, color: 'var(--text)' },
  emptyHint: { margin: '0.5rem 0 0', fontSize: '0.9rem', color: 'var(--text-muted)' },
}
