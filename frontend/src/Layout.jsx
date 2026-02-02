import { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { api } from './api'
import { useTheme } from './theme'
import { useAuth } from './auth'

export default function Layout({ children }) {
  const [projects, setProjects] = useState([])
  const [projectsOpen, setProjectsOpen] = useState(true)
  const [manageOpen, setManageOpen] = useState(true)
  const { theme, setTheme } = useTheme()
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()

  useEffect(() => {
    api.projects.list().then(setProjects).catch(() => setProjects([]))
  }, [location.pathname])

  const toggleTheme = () => setTheme(theme === 'light' ? 'dark' : 'light')

  const currentProjectId = location.pathname.match(/^\/projects\/(\d+)/)?.[1]
  const isProjectPage = !!currentProjectId

  return (
    <div style={styles.wrapper}>
      <aside className="layout-sidebar" style={styles.sidebar}>
        <div style={styles.sidebarHeader}>
          <Link to="/" className="sidebar-logo" style={styles.logo}>
            <span style={styles.logoIcon}>◉</span> ForSight
          </Link>
        </div>

        <nav style={styles.nav}>
          <div style={styles.section}>
            <button
              type="button"
              className="sidebar-section-toggle"
              style={styles.sectionLabel}
              onClick={() => setProjectsOpen((o) => !o)}
              aria-expanded={projectsOpen}
            >
              <span style={styles.sectionText}>PROJECTS</span>
              <span style={styles.chevron}>{projectsOpen ? '▼' : '▶'}</span>
            </button>
            {projectsOpen && (
              <div style={styles.sectionContent}>
                <Link to="/" className="btn-primary sidebar-new-btn" style={styles.newBtn}>
                  + New engagement
                </Link>
                <ul style={styles.projectList}>
                  {projects.map((p) => (
                    <li key={p.id}>
                      <Link
                        to={`/projects/${p.id}`}
                        className={`sidebar-project-link ${currentProjectId === String(p.id) ? 'active' : ''}`}
                        style={{
                          ...styles.projectLink,
                          ...(currentProjectId === String(p.id) ? styles.projectLinkActive : {}),
                        }}
                      >
                        {p.name}
                        {p.targets_summary && (
                          <span style={styles.projectMeta}>
                            {(p.targets_summary.ips || 0) + (p.targets_summary.domains || 0)} targets
                          </span>
                        )}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div style={styles.separator} />

          <div style={styles.section}>
            <button
              type="button"
              className="sidebar-section-toggle"
              style={styles.sectionLabel}
              onClick={() => setManageOpen((o) => !o)}
              aria-expanded={manageOpen}
            >
              <span style={styles.sectionText}>MANAGE</span>
              <span style={styles.chevron}>{manageOpen ? '▼' : '▶'}</span>
            </button>
            {manageOpen && (
              <div style={styles.sectionContent}>
                <ul style={styles.manageList}>
                  <li>
                    <Link to="/settings" className="sidebar-link" style={styles.manageLink}>Settings</Link>
                  </li>
                </ul>
              </div>
            )}
          </div>

          <div style={styles.separator} />

          <div style={styles.footerSection}>
            <span style={styles.footerLabel}>Resources</span>
            <ul style={styles.footerList}>
              <li>
                <Link to="/docs" className="sidebar-link" style={styles.footerLink} title="How to use ForSight">
                  <span style={styles.footerIcon}>📄</span> Documentation
                </Link>
              </li>
              <li>
                <Link to="/roadmap" className="sidebar-link" style={styles.footerLink} title="Planned updates">
                  <span style={styles.footerIcon}>🗺</span> Roadmap
                </Link>
              </li>
              <li>
                <Link to="/feedback" className="sidebar-link" style={styles.footerLink} title="Feature requests & bugs">
                  <span style={styles.footerIcon}>💬</span> Feedback
                </Link>
              </li>
              <li>
                <Link to="/settings" className="sidebar-link" style={styles.footerLink} title="Settings">
                  <span style={styles.footerIcon}>⚙</span> Settings
                </Link>
              </li>
            </ul>
          </div>
        </nav>
      </aside>
      <div style={styles.mainWrap}>
        <header className="layout-header" style={styles.header}>
          <span style={styles.tagline}>External pentest checklist & tool wrapper</span>
          <div style={styles.headerActions}>
            {user && (
              <span style={styles.userLabel}>{user.username}</span>
            )}
            <button
              type="button"
              onClick={toggleTheme}
              className="btn-secondary"
              style={styles.themeBtn}
              title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
              aria-label={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
            >
              {theme === 'light' ? '☀' : '☽'}
            </button>
            <Link to="/settings" className="btn-secondary" style={styles.settingsBtn}>Settings</Link>
            {user && (
              <button
                type="button"
                onClick={async () => {
                  await logout()
                  navigate('/login', { replace: true })
                }}
                className="btn-secondary"
                style={styles.logoutBtn}
              >
                Log out
              </button>
            )}
          </div>
        </header>
        <main className="main-content" style={styles.main}>{children}</main>
      </div>
    </div>
  )
}

const styles = {
  wrapper: {
    minHeight: '100vh',
    display: 'flex',
  },
  sidebar: {
    width: 260,
    flexShrink: 0,
    background: 'var(--sidebar-bg)',
    display: 'flex',
    flexDirection: 'column',
    borderRight: '1px solid var(--sidebar-border)',
  },
  sidebarHeader: {
    padding: '1rem 1rem 0.75rem',
    borderBottom: '1px solid var(--sidebar-border)',
  },
  logo: {
    color: 'var(--sidebar-text)',
    textDecoration: 'none',
    fontWeight: 700,
    fontSize: '1.1rem',
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  logoIcon: {
    color: 'var(--sidebar-accent)',
    fontSize: '1rem',
  },
  nav: {
    flex: 1,
    overflow: 'auto',
    padding: '0.5rem 0',
  },
  section: {
    marginBottom: '0.25rem',
  },
  sectionLabel: {
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.5rem 1rem',
    background: 'transparent',
    border: 'none',
    color: 'var(--sidebar-text-muted)',
    fontSize: '0.7rem',
    fontWeight: 600,
    letterSpacing: '0.05em',
    cursor: 'pointer',
    textAlign: 'left',
  },
  sectionText: {
    flex: 1,
  },
  chevron: {
    fontSize: '0.65rem',
    color: 'var(--sidebar-text-muted)',
  },
  sectionContent: {
    padding: '0.25rem 0.75rem 0.75rem',
  },
  separator: {
    height: 1,
    background: 'var(--sidebar-border)',
    margin: '0.5rem 1rem',
  },
  newBtn: {
    display: 'block',
    padding: '0.5rem 0.75rem',
    marginBottom: '0.5rem',
    background: 'var(--primary)',
    color: 'var(--primary-text)',
    borderRadius: 'var(--radius)',
    textDecoration: 'none',
    fontSize: '0.9rem',
    fontWeight: 500,
    textAlign: 'center',
    transition: 'background-color 0.15s ease',
  },
  projectList: {
    listStyle: 'none',
    margin: 0,
    padding: 0,
  },
  projectLink: {
    display: 'block',
    padding: '0.5rem 0.75rem',
    borderRadius: 'var(--radius)',
    color: 'var(--sidebar-text)',
    textDecoration: 'none',
    fontSize: '0.9rem',
    marginBottom: '0.25rem',
    transition: 'background-color 0.15s ease, color 0.15s ease',
  },
  projectLinkActive: {
    background: 'var(--sidebar-accent)',
    color: '#fff',
  },
  projectMeta: {
    display: 'block',
    fontSize: '0.75rem',
    color: 'var(--sidebar-text-muted)',
  },
  manageList: {
    listStyle: 'none',
    margin: 0,
    padding: 0,
  },
  manageLink: {
    display: 'block',
    padding: '0.4rem 1rem',
    color: 'var(--sidebar-text)',
    textDecoration: 'none',
    fontSize: '0.9rem',
    transition: 'color 0.15s ease',
  },
  footerSection: {
    padding: '0.5rem 1rem 0.75rem',
  },
  footerLabel: {
    display: 'block',
    fontSize: '0.7rem',
    fontWeight: 600,
    color: 'var(--sidebar-text-muted)',
    letterSpacing: '0.05em',
    marginBottom: '0.35rem',
  },
  footerList: {
    listStyle: 'none',
    margin: 0,
    padding: 0,
  },
  footerLink: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.35rem 0',
    color: 'var(--sidebar-text-muted)',
    textDecoration: 'none',
    fontSize: '0.85rem',
    transition: 'color 0.15s ease',
  },
  footerIcon: {
    fontSize: '0.9rem',
    opacity: 0.9,
  },
  mainWrap: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    minWidth: 0,
  },
  header: {
    padding: '0.75rem 1.5rem',
    background: 'var(--surface)',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.5rem',
  },
  tagline: {
    color: 'var(--text-muted)',
    fontSize: '0.9rem',
  },
  headerActions: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  themeBtn: {
    padding: '0.4rem 0.6rem',
    minWidth: 36,
    fontSize: '1.1rem',
    lineHeight: 1,
  },
  settingsBtn: {
    padding: '0.4rem 0.75rem',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    color: 'var(--text)',
    textDecoration: 'none',
    fontSize: '0.9rem',
  },
  userLabel: {
    fontSize: '0.875rem',
    color: 'var(--text-muted)',
    marginRight: '0.25rem',
  },
  logoutBtn: {
    padding: '0.4rem 0.75rem',
    fontSize: '0.9rem',
  },
  main: {
    flex: 1,
    padding: '1.5rem',
    maxWidth: 1200,
    margin: '0 auto',
    width: '100%',
  },
}
