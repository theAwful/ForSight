/**
 * frontend/src/Layout.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Drop-in replacement for the existing Layout.jsx.
 * Keeps all existing import paths and hook contracts intact.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import { useAuth } from './auth'
import { useTheme } from './theme'
import { api } from './api'

// ── Icons (inline SVG — no extra dep) ────────────────────────────────────────

const Icon = ({ d, size = 15, stroke = 1.75 }) => (
  <svg
    width={size} height={size}
    viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth={stroke}
    strokeLinecap="round" strokeLinejoin="round"
    style={{ flexShrink: 0, display: 'block' }}
  >
    {Array.isArray(d)
      ? d.map((p, i) => <path key={i} d={p} />)
      : <path d={d} />}
  </svg>
)

const Icons = {
  grid:     'M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z',
  folder:   ['M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'],
  plus:     'M12 5v14M5 12h14',
  chevron:  'M6 9l6 6 6-6',
  chevronR: 'M9 18l6-6-6-6',
  sun:      ['M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z'],
  moon:     'M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z',
  settings: ['M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z','M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z'],
  logout:   ['M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4','M16 17l5-5-5-5','M21 12H9'],
  book:     ['M4 19.5A2.5 2.5 0 0 1 6.5 17H20','M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z'],
  map:      ['M1 6v16l7-4 8 4 7-4V2l-7 4-8-4-7 4z','M8 2v16M16 6v16'],
  msg:      ['M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z'],
  menu:     'M3 12h18M3 6h18M3 18h18',
  x:        'M18 6L6 18M6 6l12 12',
  target:   ['M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z','M12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12z','M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z'],
}

// ── Sidebar project list ──────────────────────────────────────────────────────

function SidebarProjects({ currentProjectId }) {
  const [projects, setProjects] = useState([])
  const [open, setOpen]         = useState(true)
  const [loading, setLoading]   = useState(true)

  useEffect(() => {
    api.projects?.list?.()
      .then(d => setProjects(Array.isArray(d) ? d : (d?.projects ?? [])))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return (
    <div>
      <button
        type="button"
        className="sidebar-section-toggle"
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
      >
        <span>Engagements</span>
        <svg
          width="10" height="10" viewBox="0 0 24 24"
          fill="none" stroke="currentColor" strokeWidth="2.5"
          strokeLinecap="round" strokeLinejoin="round"
          style={{ transform: open ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s' }}
        >
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="sidebar-projects-list">
          {loading && (
            <div style={{ padding: '6px 22px', fontSize: '0.73rem', color: 'var(--sidebar-text-muted)' }}>
              Loading…
            </div>
          )}
          {!loading && projects.length === 0 && (
            <div style={{ padding: '6px 22px', fontSize: '0.73rem', color: 'var(--sidebar-text-muted)' }}>
              No engagements yet
            </div>
          )}
          {projects.slice(0, 12).map(p => {
            const id     = p.id ?? p.project_id
            const name   = p.name ?? p.client_name ?? `Project ${id}`
            const active = String(id) === String(currentProjectId)
            return (
              <Link
                key={id}
                to={`/projects/${id}`}
                className={`sidebar-project-link${active ? ' active' : ''}`}
                title={name}
              >
                <span className="sidebar-project-dot" />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {name}
                </span>
              </Link>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Main Layout ───────────────────────────────────────────────────────────────

export default function Layout({ children }) {
  const { user, logout }          = useAuth()
  const { theme, toggleTheme }    = useTheme()
  const location                  = useLocation()
  const navigate                  = useNavigate()
  const { projectId }             = useParams()
  const [mobileOpen, setMobileOpen] = useState(false)

  // Close mobile menu on route change
  useEffect(() => { setMobileOpen(false) }, [location.pathname])

  const isDark = theme === 'dark'

  const handleLogout = async () => {
    try { await logout() } catch { /* ignore */ }
    navigate('/login')
  }

  const navLinks = [
    { to: '/',         icon: Icons.grid,    label: 'Engagements' },
    { to: '/roadmap',  icon: Icons.map,     label: 'Roadmap'     },
    { to: '/feedback', icon: Icons.msg,     label: 'Feedback'    },
    { to: '/docs',     icon: Icons.book,    label: 'Docs'        },
  ]

  const isActive = (to) => {
    if (to === '/') return location.pathname === '/'
    return location.pathname.startsWith(to)
  }

  // ── Sidebar content (reused for mobile drawer) ──────────────────────────

  const SidebarContent = () => (
    <>
      {/* Logo */}
      <Link to="/" className="sidebar-logo">
        <span className="sidebar-logo-mark">FS</span>
        <span className="sidebar-logo-text">ForSight</span>
      </Link>

      <nav className="sidebar-nav" aria-label="Primary navigation">
        {/* New engagement */}
        <div style={{ padding: '8px 0 4px' }}>
          <Link to="/" className="sidebar-new-btn">
            <Icon d={Icons.plus} size={13} stroke={2.5} />
            New engagement
          </Link>
        </div>

        {/* Main nav */}
        <div style={{ marginTop: 4 }}>
          {navLinks.map(({ to, icon, label }) => (
            <Link
              key={to}
              to={to}
              className={`sidebar-link${isActive(to) ? ' active' : ''}`}
              aria-current={isActive(to) ? 'page' : undefined}
            >
              <Icon d={icon} size={14} />
              {label}
            </Link>
          ))}
        </div>

        {/* Projects */}
        <div style={{ marginTop: 8 }}>
          <SidebarProjects currentProjectId={projectId} />
        </div>
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <Link
          to="/settings"
          className={`sidebar-link${isActive('/settings') ? ' active' : ''}`}
        >
          <Icon d={Icons.settings} size={14} />
          Settings
        </Link>

        <button
          type="button"
          className="sidebar-link"
          onClick={toggleTheme}
          style={{ width: '100%' }}
          aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          <Icon d={isDark ? Icons.sun : Icons.moon} size={14} />
          {isDark ? 'Light mode' : 'Dark mode'}
        </button>

        {user && (
          <button
            type="button"
            className="sidebar-link"
            onClick={handleLogout}
            style={{ width: '100%' }}
          >
            <Icon d={Icons.logout} size={14} />
            Sign out
          </button>
        )}

        {/* Version tag */}
        <div style={{
          padding: '8px 18px 0',
          fontSize: '0.62rem',
          color: 'var(--sidebar-text-faint)',
          fontFamily: 'var(--font-mono)',
          letterSpacing: '0.04em',
        }}>
          forsight · v0.1
        </div>
      </div>
    </>
  )

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>

      {/* ── Desktop sidebar ── */}
      <aside
        className="layout-sidebar"
        style={{ display: 'flex', flexDirection: 'column' }}
        aria-label="App navigation"
      >
        <SidebarContent />
      </aside>

      {/* ── Mobile drawer overlay ── */}
      {mobileOpen && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 200,
            display: 'flex',
          }}
          onClick={() => setMobileOpen(false)}
        >
          {/* Scrim */}
          <div style={{
            position: 'absolute', inset: 0,
            background: 'rgba(0,0,0,0.55)',
            backdropFilter: 'blur(2px)',
          }} />

          {/* Drawer */}
          <aside
            style={{
              position: 'relative', zIndex: 1,
              width: 'var(--sidebar-w)',
              background: 'var(--sidebar-bg)',
              display: 'flex', flexDirection: 'column',
              height: '100%',
              borderRight: '1px solid var(--sidebar-border)',
              animation: 'fadeSlideIn 0.18s ease',
            }}
            onClick={e => e.stopPropagation()}
            aria-label="Mobile navigation"
          >
            <SidebarContent />
          </aside>
        </div>
      )}

      {/* ── Main area ── */}
      <div className="layout-main">

        {/* Top header */}
        <header className="layout-header">
          {/* Mobile hamburger */}
          <button
            type="button"
            onClick={() => setMobileOpen(v => !v)}
            aria-label="Toggle navigation"
            style={{
              marginRight: 12,
              display: 'none',  // shown via media query below
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              padding: '4px',
            }}
            className="mobile-menu-btn"
          >
            <Icon d={mobileOpen ? Icons.x : Icons.menu} size={18} stroke={1.75} />
          </button>

          {/* Breadcrumb / page context */}
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <HeaderBreadcrumb location={location} projectId={projectId} />
          </div>

          {/* Right slot */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {user && (
              <div style={{
                fontSize: '0.75rem',
                color: 'var(--text-faint)',
                fontWeight: 500,
                display: 'none', // show on wider screens
              }} className="header-username">
                {user.username ?? user.email ?? ''}
              </div>
            )}

            <button
              type="button"
              onClick={toggleTheme}
              aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              style={{
                background: 'transparent',
                border: '1px solid var(--border)',
                color: 'var(--text-muted)',
                padding: '5px',
                borderRadius: 'var(--radius-sm)',
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <Icon d={isDark ? Icons.sun : Icons.moon} size={14} />
            </button>
          </div>
        </header>

        {/* Page content */}
        <main className="layout-content main-content" id="main-content">
          {children}
        </main>
      </div>

      {/* Mobile responsive */}
      <style>{`
        @media (max-width: 768px) {
          .layout-sidebar { display: none !important; }
          .mobile-menu-btn { display: flex !important; }
          .layout-content { padding: 16px; }
          .layout-header { padding: 0 16px; }
        }
        @media (min-width: 769px) {
          .header-username { display: block !important; }
        }
      `}</style>
    </div>
  )
}

// ── Header breadcrumb ─────────────────────────────────────────────────────────

function HeaderBreadcrumb({ location, projectId }) {
  const [projectName, setProjectName] = useState(null)

  useEffect(() => {
    if (!projectId) { setProjectName(null); return }
    api.projects?.get?.(projectId)
      .then(p => setProjectName(p?.name ?? p?.client_name ?? `Project ${projectId}`))
      .catch(() => setProjectName(null))
  }, [projectId])

  const segments = location.pathname.split('/').filter(Boolean)

  // Root
  if (segments.length === 0) {
    return (
      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text)' }}>
        Engagements
      </span>
    )
  }

  // Settings / roadmap / feedback / docs
  const staticLabels = {
    settings: 'Settings',
    roadmap:  'Roadmap',
    feedback: 'Feedback',
    docs:     'Docs',
  }
  if (staticLabels[segments[0]]) {
    return (
      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text)' }}>
        {staticLabels[segments[0]]}
      </span>
    )
  }

  // Project
  if (segments[0] === 'projects' && projectId) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
        <Link
          to="/"
          style={{ fontSize: '0.78rem', color: 'var(--text-faint)', whiteSpace: 'nowrap' }}
        >
          Engagements
        </Link>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--border-strong)', flexShrink: 0 }}>
          <path d="M9 18l6-6-6-6" />
        </svg>
        <span style={{
          fontSize: '0.8rem', fontWeight: 600, color: 'var(--text)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {projectName ?? `Project ${projectId}`}
        </span>
      </div>
    )
  }

  return null
}
