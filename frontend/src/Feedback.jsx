import { useState, useEffect } from 'react'
import { api } from './api'

const KIND_LABELS = { feature: 'Feature request', bug: 'Bug report' }
const STATUS_LABELS = { open: 'Open', in_progress: 'In progress', done: 'Done' }

export default function Feedback() {
  const [features, setFeatures] = useState([])
  const [bugs, setBugs] = useState([])
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('features')
  const [submitting, setSubmitting] = useState(false)
  const [form, setForm] = useState({ title: '', description: '' })

  const load = () => {
    api.feedback.list('feature').then((data) => setFeatures(Array.isArray(data) ? data : [])).catch(() => setFeatures([]))
    api.feedback.list('bug').then((data) => setBugs(Array.isArray(data) ? data : [])).catch(() => setBugs([]))
  }

  useEffect(() => {
    setLoading(true)
    Promise.all([api.feedback.list('feature'), api.feedback.list('bug')])
      .then(([f, b]) => {
        setFeatures(Array.isArray(f) ? f : [])
        setBugs(Array.isArray(b) ? b : [])
      })
      .catch(() => { setFeatures([]); setBugs([]) })
      .finally(() => setLoading(false))
  }, [])

  const onSubmit = (e) => {
    e.preventDefault()
    if (!form.title.trim()) return
    setSubmitting(true)
    const kind = tab === 'features' ? 'feature' : 'bug'
    api.feedback
      .create({ kind, title: form.title.trim(), description: form.description.trim() || undefined })
      .then(() => {
        setForm({ title: '', description: '' })
        load()
      })
      .catch((err) => window.alert(err?.body?.detail || err?.message || 'Failed to submit'))
      .finally(() => setSubmitting(false))
  }

  if (loading) return <div className="main-content" style={styles.msg}>Loading…</div>

  const list = tab === 'features' ? features : bugs
  const kindLabel = tab === 'features' ? 'Feature requests' : 'Bug reports'

  return (
    <div className="main-content" style={styles.wrapper}>
      <h1 style={styles.h1}>Feature requests & bug tracking</h1>
      <p style={styles.lead}>
        Submit feature requests or report bugs. View and track existing items below.
      </p>

      <div style={styles.tabs}>
        {['features', 'bugs'].map((t) => (
          <button
            key={t}
            type="button"
            className={`tab-btn ${tab === t ? 'tab-btn-active' : ''}`}
            style={{ ...styles.tab, ...(tab === t ? styles.tabActive : {}) }}
            onClick={() => setTab(t)}
          >
            {t === 'features' ? 'Feature requests' : 'Bug reports'}
          </button>
        ))}
      </div>

      <section className="card" style={styles.formSection}>
        <h2 style={styles.h2}>Submit {tab === 'features' ? 'a feature request' : 'a bug report'}</h2>
        <form onSubmit={onSubmit} style={styles.form}>
          <input
            type="text"
            placeholder={tab === 'features' ? 'Short title for your feature idea' : 'Short description of the bug'}
            value={form.title}
            onChange={(e) => setForm({ ...form, title: e.target.value })}
            style={styles.input}
            required
          />
          <textarea
            placeholder="Details (optional)"
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            style={styles.textarea}
            rows={3}
          />
          <button type="submit" className="btn-primary" disabled={submitting} style={styles.submitBtn}>
            {submitting ? 'Submitting…' : `Submit ${tab === 'features' ? 'feature request' : 'bug report'}`}
          </button>
        </form>
      </section>

      <section style={styles.section}>
        <h2 style={styles.h2}>{kindLabel} ({list.length})</h2>
        {list.length === 0 ? (
          <p style={styles.muted}>None yet. Be the first to submit one above.</p>
        ) : (
          <ul style={styles.list}>
            {list.map((item) => (
              <li key={item.id} className="card" style={styles.item}>
                <div style={styles.itemTop}>
                  <strong style={styles.title}>{item.title}</strong>
                  <span style={styles.status}>{STATUS_LABELS[item.status] || item.status}</span>
                </div>
                {item.description && <p style={styles.desc}>{item.description}</p>}
                <span style={styles.meta}>
                  #{item.id} · {new Date(item.created_at).toLocaleDateString()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}

const styles = {
  wrapper: { maxWidth: 720, margin: '0 auto' },
  h1: { margin: '0 0 0.5rem 0', fontSize: '1.75rem', fontWeight: 700 },
  lead: { fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '1.5rem', lineHeight: 1.6 },
  tabs: { display: 'flex', gap: '0.25rem', marginBottom: '1.5rem' },
  tab: { padding: '0.5rem 1rem', borderRadius: 'var(--radius)', background: 'transparent', color: 'var(--text-muted)' },
  tabActive: { background: 'var(--surface)', color: 'var(--accent)', border: '1px solid var(--border)' },
  formSection: { padding: '1.25rem', marginBottom: '2rem' },
  h2: { margin: '0 0 1rem 0', fontSize: '1.1rem', fontWeight: 600 },
  form: { display: 'flex', flexDirection: 'column', gap: '0.75rem', maxWidth: 480 },
  input: { padding: '0.5rem 0.75rem', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)' },
  textarea: { padding: '0.5rem 0.75rem', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', resize: 'vertical', fontFamily: 'inherit' },
  submitBtn: {},
  section: { marginBottom: '1.5rem' },
  list: { listStyle: 'none', margin: 0, padding: 0 },
  item: { padding: '1rem', marginBottom: '0.75rem', border: '1px solid var(--border)', borderRadius: 'var(--radius)' },
  itemTop: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '0.35rem' },
  title: { fontSize: '1rem' },
  status: { fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 500 },
  desc: { margin: '0 0 0.35rem 0', fontSize: '0.9rem', color: 'var(--text-muted)', lineHeight: 1.5 },
  meta: { fontSize: '0.75rem', color: 'var(--text-muted)' },
  msg: { color: 'var(--text-muted)' },
  muted: { color: 'var(--text-muted)' },
}
