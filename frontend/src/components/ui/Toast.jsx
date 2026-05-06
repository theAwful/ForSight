import { createContext, useContext, useState, useCallback, useRef } from 'react'

const ToastContext = createContext(null)

const DURATIONS = { success: 4000, info: 4000, warning: 6000, error: 8000 }

/**
 * ToastProvider — wrap your app (or Layout) with this.
 * Then call useToast() in any component to show toasts.
 *
 * Usage:
 *   const { toast } = useToast()
 *   toast.success('Scan launched!')
 *   toast.error('Launch failed: ' + message)
 *   toast.warning('Nessus returned a warning.')
 *   toast.info('Importing results…')
 */
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const idRef = useRef(0)

  const show = useCallback((message, variant = 'info') => {
    const id = ++idRef.current
    const duration = DURATIONS[variant] || 4000
    setToasts((prev) => {
      // Max 3 visible; remove oldest if needed
      const next = prev.length >= 3 ? prev.slice(1) : prev
      return [...next, { id, message, variant, exiting: false }]
    })
    setTimeout(() => {
      // Mark as exiting to trigger animation
      setToasts((prev) => prev.map((t) => t.id === id ? { ...t, exiting: true } : t))
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id))
      }, 180)
    }, duration)
    return id
  }, [])

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.map((t) => t.id === id ? { ...t, exiting: true } : t))
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 180)
  }, [])

  const api = {
    success: (msg) => show(msg, 'success'),
    error:   (msg) => show(msg, 'error'),
    warning: (msg) => show(msg, 'warning'),
    info:    (msg) => show(msg, 'info'),
    show,
    dismiss,
  }

  return (
    <ToastContext.Provider value={api}>
      {children}
      {/* Toast container */}
      <div
        aria-live="polite"
        aria-atomic="false"
        style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
          maxWidth: '380px',
          width: '100%',
          pointerEvents: 'none',
        }}
      >
        {toasts.map((t) => (
          <Toast key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return { toast: ctx }
}

function Toast({ toast, onDismiss }) {
  const { message, variant, exiting } = toast

  const ICONS = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' }
  const BORDER_COLORS = {
    success: 'var(--color-success)',
    error:   'var(--color-danger)',
    warning: 'var(--color-warning)',
    info:    'var(--color-accent)',
  }

  return (
    <div
      role="alert"
      style={{
        background: 'var(--color-bg-elevated)',
        border: '1px solid var(--color-border)',
        borderLeft: `4px solid ${BORDER_COLORS[variant] || 'var(--color-accent)'}`,
        borderRadius: 'var(--radius-md)',
        padding: '12px 14px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '10px',
        boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
        pointerEvents: 'all',
        animation: exiting
          ? 'toast-out 0.18s ease-in forwards'
          : 'toast-in 0.2s ease-out forwards',
        minWidth: '280px',
        maxWidth: '380px',
      }}
    >
      <span style={{ fontSize: '0.9rem', flexShrink: 0, color: BORDER_COLORS[variant] }}>
        {ICONS[variant] || 'ℹ'}
      </span>
      <span style={{ flex: 1, fontSize: '0.85rem', color: 'var(--color-text-primary)', lineHeight: 1.45 }}>
        {message}
      </span>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss notification"
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--color-text-disabled)',
          cursor: 'pointer',
          fontSize: '0.8rem',
          padding: '0',
          flexShrink: 0,
          lineHeight: 1,
        }}
      >
        ✕
      </button>
    </div>
  )
}
