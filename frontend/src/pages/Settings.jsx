import { useState, useEffect, useCallback } from 'react'
import { useTheme } from '../theme'
import { api } from '../api'
import ToolStatusTable from '../components/settings/ToolStatusTable'
import { useToast } from '../components/ui/Toast'

export default function Settings() {
  const { theme, setTheme } = useTheme()
  const { toast } = useToast()

  const [tools, setTools] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [toolError, setToolError] = useState(null)

  const fetchTools = useCallback(async (isRefresh = false) => {
    if (isRefresh) setIsRefreshing(true)
    else setIsLoading(true)
    setToolError(null)
    try {
      const data = await api.tools.status()
      setTools(data)
    } catch (err) {
      setToolError(err?.message || 'Failed to load tool status')
    } finally {
      setIsLoading(false)
      setIsRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchTools()
  }, [fetchTools])

  const handleUpdatePath = useCallback(async (key, path) => {
    try {
      const updated = await api.tools.updatePath(key, path)
      // Merge updated tool back into the list
      setTools((prev) => prev.map((t) => (t.key === updated.key ? updated : t)))
      toast.success(`Updated path for ${updated.display_name}. Status: ${updated.status}.`)
    } catch (err) {
      const msg = err?.body?.detail || err?.message || 'Failed to update path'
      toast.error(msg)
      throw new Error(msg)
    }
  }, [toast])

  return (
    <div style={styles.wrapper}>
      <h1 style={styles.title}>Settings</h1>

      {/* ── Appearance ─────────────────────────────────────── */}
      <section style={styles.card}>
        <h2 style={styles.sectionTitle}>Appearance</h2>
        <p style={styles.sectionDesc}>
          Choose light or dark mode. You can also toggle using the button in the top bar.
        </p>
        <div style={styles.themeRow}>
          <button
            type="button"
            onClick={() => setTheme('dark')}
            style={{
              ...styles.themeBtn,
              ...(theme === 'dark' ? styles.themeBtnActive : styles.themeBtnInactive),
            }}
          >
            ☽ Dark (recommended)
          </button>
          <button
            type="button"
            onClick={() => setTheme('light')}
            style={{
              ...styles.themeBtn,
              ...(theme === 'light' ? styles.themeBtnActive : styles.themeBtnInactive),
            }}
          >
            ☀ Light
          </button>
        </div>
      </section>

      {/* ── Tool Management ────────────────────────────────── */}
      <section style={styles.card}>
        <div style={styles.sectionHeader}>
          <div>
            <h2 style={styles.sectionTitle}>Tool Management</h2>
            <p style={styles.sectionDesc}>
              Current status of all configured pentesting tools on this host.
              Click <strong>Edit path</strong> to update a binary location without restarting the backend.
            </p>
          </div>
          <button
            type="button"
            onClick={() => fetchTools(true)}
            disabled={isRefreshing}
            style={styles.refreshBtn}
            aria-label="Refresh tool status"
          >
            {isRefreshing ? '↻ Refreshing…' : '↻ Refresh'}
          </button>
        </div>

        <ToolStatusTable
          tools={tools}
          onRefresh={() => fetchTools(true)}
          onUpdatePath={handleUpdatePath}
          isLoading={isLoading}
          isRefreshing={isRefreshing}
          error={toolError}
        />

        <p style={styles.footerNote}>
          To persist path changes across backend restarts, set{' '}
          <code style={styles.code}>FORSIGHT_&lt;TOOL_KEY&gt;_PATH</code> in your{' '}
          <code style={styles.code}>.env</code> file.
        </p>
      </section>

      {/* ── Nessus / Tenable Config ────────────────────────── */}
      <section style={styles.card}>
        <h2 style={styles.sectionTitle}>Nessus / Tenable Configuration</h2>
        <p style={styles.sectionDesc}>
          Nessus credentials are configured via environment variables in your{' '}
          <code style={styles.code}>.env</code> file. Set these to enable the Nessus tab:
        </p>
        <div style={styles.envList}>
          {[
            ['FORSIGHT_TENABLE_BASE_URL', 'Nessus Pro URL (default: https://127.0.0.1:8834)'],
            ['FORSIGHT_TENABLE_ACCESS_KEY', 'API access key (for scan listing and import)'],
            ['FORSIGHT_TENABLE_SECRET_KEY', 'API secret key'],
            ['FORSIGHT_TENABLE_USERNAME', 'Username (for Selenium: launch, create, delete)'],
            ['FORSIGHT_TENABLE_PASSWORD', 'Password (for Selenium)'],
            ['FORSIGHT_TENABLE_VERIFY_SSL', 'Set true to verify TLS (default: false)'],
            ['FORSIGHT_SELENIUM_DEBUG', 'Set 1 to save Selenium failure screenshots to /tmp/'],
          ].map(([key, desc]) => (
            <div key={key} style={styles.envRow}>
              <code style={{ ...styles.code, flexShrink: 0 }}>{key}</code>
              <span style={styles.envDesc}>{desc}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── About ──────────────────────────────────────────── */}
      <section style={styles.card}>
        <h2 style={styles.sectionTitle}>About</h2>
        <p style={styles.sectionDesc}>
          ForSight — external pentest checklist and tool wrapper.
        </p>
        <ul style={styles.ul}>
          <li><a href="/api/health" target="_blank" rel="noopener noreferrer" style={styles.link}>Health check</a></li>
          <li><a href="/docs" target="_blank" rel="noopener noreferrer" style={styles.link}>Documentation</a></li>
          <li><a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer" style={styles.link}>API docs (Swagger)</a></li>
        </ul>
      </section>
    </div>
  )
}

const styles = {
  wrapper: {
    maxWidth: '900px',
  },
  title: {
    margin: '0 0 1.25rem 0',
    fontSize: '1.5rem',
    fontWeight: 700,
    color: 'var(--color-text-primary)',
  },
  card: {
    background: 'var(--color-bg-surface)',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-lg)',
    padding: '20px 24px',
    marginBottom: '16px',
  },
  sectionHeader: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '16px',
    marginBottom: '14px',
    flexWrap: 'wrap',
  },
  sectionTitle: {
    margin: '0 0 4px 0',
    fontSize: '1rem',
    fontWeight: 600,
    color: 'var(--color-text-primary)',
  },
  sectionDesc: {
    margin: '0 0 14px 0',
    fontSize: '0.875rem',
    color: 'var(--color-text-secondary)',
    lineHeight: 1.55,
  },
  themeRow: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
  },
  themeBtn: {
    padding: '7px 18px',
    borderRadius: 'var(--radius-md)',
    fontSize: '0.875rem',
    cursor: 'pointer',
    fontWeight: 500,
    border: '1px solid transparent',
    transition: 'all 0.15s',
  },
  themeBtnActive: {
    background: 'var(--color-accent)',
    color: '#fff',
    borderColor: 'var(--color-accent)',
  },
  themeBtnInactive: {
    background: 'transparent',
    color: 'var(--color-text-secondary)',
    borderColor: 'var(--color-border)',
  },
  refreshBtn: {
    padding: '6px 14px',
    background: 'transparent',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-md)',
    color: 'var(--color-text-secondary)',
    fontSize: '0.82rem',
    cursor: 'pointer',
    flexShrink: 0,
    whiteSpace: 'nowrap',
  },
  footerNote: {
    marginTop: '12px',
    fontSize: '0.78rem',
    color: 'var(--color-text-disabled)',
  },
  envList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  envRow: {
    display: 'flex',
    alignItems: 'baseline',
    gap: '12px',
    flexWrap: 'wrap',
  },
  envDesc: {
    fontSize: '0.82rem',
    color: 'var(--color-text-secondary)',
  },
  ul: {
    margin: '0',
    paddingLeft: '1.25rem',
    lineHeight: 1.75,
    fontSize: '0.875rem',
  },
  link: {
    color: 'var(--color-accent)',
  },
  code: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.82em',
    background: 'var(--color-bg-elevated)',
    padding: '1px 5px',
    borderRadius: '3px',
    color: 'var(--color-text-primary)',
  },
}
