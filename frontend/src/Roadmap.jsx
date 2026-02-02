import { useState, useEffect } from 'react'
import { api } from './api'

const STATUS_LABELS = { planned: 'Planned', in_progress: 'In progress', done: 'Done' }
const STATUS_COLORS = { planned: 'var(--text-muted)', in_progress: 'var(--accent)', done: 'var(--primary)' }

export default function Roadmap() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.roadmap.list()
      .then((data) => setItems(Array.isArray(data) ? data : []))
      .catch(() => setItems([]))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="main-content" style={styles.msg}>Loading roadmap…</div>

  const byCategory = {}
  items.forEach((item) => {
    const cat = item.category || 'Other'
    if (!byCategory[cat]) byCategory[cat] = []
    byCategory[cat].push(item)
  })

  return (
    <div className="main-content" style={styles.wrapper}>
      <h1 style={styles.h1}>Roadmap</h1>
      <p style={styles.lead}>
        Planned updates and future features for ForSight. Priorities may change based on feedback.
      </p>
      {items.length === 0 ? (
        <p style={styles.muted}>No roadmap items yet.</p>
      ) : (
        Object.entries(byCategory).map(([category, list]) => (
          <section key={category} style={styles.section}>
            <h2 style={styles.h2}>{category}</h2>
            <ul style={styles.list}>
              {list.map((item) => (
                <li key={item.id} className="card" style={styles.item}>
                  <div style={styles.itemTop}>
                    <strong style={styles.title}>{item.title}</strong>
                    <span
                      style={{
                        ...styles.status,
                        color: STATUS_COLORS[item.status] || STATUS_COLORS.planned,
                      }}
                    >
                      {STATUS_LABELS[item.status] || item.status}
                    </span>
                  </div>
                  {item.description && (
                    <p style={styles.desc}>{item.description}</p>
                  )}
                </li>
              ))}
            </ul>
          </section>
        ))
      )}
    </div>
  )
}

const styles = {
  wrapper: { maxWidth: 720, margin: '0 auto' },
  h1: { margin: '0 0 0.5rem 0', fontSize: '1.75rem', fontWeight: 700 },
  lead: { fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '1.5rem', lineHeight: 1.6 },
  section: { marginBottom: '2rem' },
  h2: { margin: '0 0 0.75rem 0', fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-muted)' },
  list: { listStyle: 'none', margin: 0, padding: 0 },
  item: { padding: '1rem', marginBottom: '0.75rem', border: '1px solid var(--border)', borderRadius: 'var(--radius)' },
  itemTop: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '0.35rem' },
  title: { fontSize: '1rem' },
  status: { fontSize: '0.8rem', fontWeight: 600 },
  desc: { margin: 0, fontSize: '0.9rem', color: 'var(--text-muted)', lineHeight: 1.5 },
  msg: { color: 'var(--text-muted)' },
  muted: { color: 'var(--text-muted)' },
}
