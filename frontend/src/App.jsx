/**
 * UPDATED frontend/src/App.jsx
 * ============================
 * Only change from the original: wraps the app with ToastProvider
 * so any component can call useToast().
 *
 * Replace the existing App.jsx with this file.
 */

import { BrowserRouter, Routes, Route, Navigate, useLocation, Outlet } from 'react-router-dom'
import { ThemeProvider } from './theme'
import { AuthProvider, useAuth } from './auth'
import { ToastProvider } from './components/ui/Toast'
import Layout from './Layout'
import Login from './Login'
import ProjectList from './ProjectList'
import ProjectDetail from './ProjectDetail'
import Settings from './pages/Settings'
import Roadmap from './Roadmap'
import Feedback from './Feedback'
import ErrorBoundary from './ErrorBoundary'

function ProtectedLayout() {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--color-bg-primary)',
      }}>
        <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.95rem' }}>
          Checking authentication…
        </span>
      </div>
    )
  }
  if (!user) {
    const redirect = location.pathname + location.search
    return (
      <Navigate
        to={redirect ? `/login?redirect=${encodeURIComponent(redirect)}` : '/login'}
        replace
      />
    )
  }
  return (
    <Layout>
      <Outlet />
    </Layout>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          {/* ToastProvider must be inside ThemeProvider so toasts inherit CSS vars */}
          <ToastProvider>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route element={<ProtectedLayout />}>
                <Route path="/" element={<ProjectList />} />
                <Route
                  path="/projects/:projectId"
                  element={
                    <ErrorBoundary>
                      <ProjectDetail />
                    </ErrorBoundary>
                  }
                />
                <Route path="/settings" element={<Settings />} />
                <Route path="/docs" element={<Navigate to="/docs/" replace />} />
                <Route path="/roadmap" element={<Roadmap />} />
                <Route path="/feedback" element={<Feedback />} />
              </Route>
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}
