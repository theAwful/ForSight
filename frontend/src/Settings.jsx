import { useTheme } from './theme'

export default function Settings() {
  const { theme, setTheme } = useTheme()

  return (
    <div style={styles.wrapper}>
      <h1 style={styles.title}>Settings</h1>

      <section className="card" style={styles.section}>
        <h2 style={styles.sectionTitle}>Appearance</h2>
        <p style={styles.sectionDesc}>Choose light or dark mode. You can also toggle from the header (top right).</p>
        <div style={styles.themeRow}>
          <button
            type="button"
            className={theme === 'light' ? 'btn-primary' : 'btn-secondary'}
            style={styles.themeBtn}
            onClick={() => setTheme('light')}
          >
            ☀ Light
          </button>
          <button
            type="button"
            className={theme === 'dark' ? 'btn-primary' : 'btn-secondary'}
            style={styles.themeBtn}
            onClick={() => setTheme('dark')}
          >
            ☽ Dark
          </button>
        </div>
      </section>

      <section className="card" style={styles.section}>
        <h2 style={styles.sectionTitle}>About</h2>
        <p style={styles.sectionDesc}>
          ForSight — external pentest checklist and tool wrapper. API runs under <code style={styles.code}>/api</code>.
        </p>
        <ul style={styles.ul}>
          <li><a href="/api/health" target="_blank" rel="noopener noreferrer">Health check</a></li>
          <li><a href="/api/projects" target="_blank" rel="noopener noreferrer">Projects API</a></li>
        </ul>
      </section>

      <section className="card" style={styles.section}>
        <h2 style={styles.sectionTitle}>Projects & targets</h2>
        <p style={styles.sectionDesc}>
          Create engagements from the home page. Upload or paste ROE (IPs and domains) in a project. Edit targets in the <strong>Current targets</strong> panel; all tools use that list.
        </p>
      </section>
    </div>
  )
}

const styles = {
  wrapper: { maxWidth: 560 },
  title: { margin: '0 0 1rem 0', fontSize: '1.5rem', fontWeight: 600 },
  section: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: '1.25rem',
    marginBottom: '1rem',
  },
  sectionTitle: { margin: '0 0 0.35rem 0', fontSize: '1rem', fontWeight: 600 },
  sectionDesc: { margin: '0 0 0.75rem 0', fontSize: '0.9rem', color: 'var(--text-muted)', lineHeight: 1.5 },
  themeRow: { display: 'flex', gap: '0.5rem', flexWrap: 'wrap' },
  themeBtn: { minWidth: 100 },
  ul: { margin: 0, paddingLeft: '1.25rem', lineHeight: 1.6, fontSize: '0.9rem' },
  code: { background: 'var(--bg)', padding: '0.1rem 0.35rem', borderRadius: 'var(--radius)', fontFamily: 'var(--font-mono)', fontSize: '0.85em' },
}
