import { BrowserRouter, Routes, Route, Navigate, useLocation, Outlet } from 'react-router-dom'
import { ThemeProvider } from './theme'
import { AuthProvider, useAuth } from './auth'
import Layout from './Layout'
import Login from './Login'
import ProjectList from './ProjectList'
import ProjectDetail from './ProjectDetail'
import Settings from './Settings'
import Roadmap from './Roadmap'
import Feedback from './Feedback'
import ErrorBoundary from './ErrorBoundary'

function ProtectedLayout() {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)' }}>
        <span style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>Checking authentication…</span>
      </div>
    )
  }
  if (!user) {
    const redirect = location.pathname + location.search
    return <Navigate to={redirect ? `/login?redirect=${encodeURIComponent(redirect)}` : '/login'} replace />
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
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}
