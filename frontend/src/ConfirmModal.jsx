/** Styled confirmation modal (replaces window.confirm). */
export default function ConfirmModal({ open, title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false, onConfirm, onCancel, loading = false }) {
  if (!open) return null
  return (
    <div style={styles.backdrop} onClick={onCancel} role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <div style={styles.box} onClick={(e) => e.stopPropagation()}>
        <h3 id="confirm-title" style={styles.title}>{title}</h3>
        <p style={styles.message}>{message}</p>
        <div style={styles.actions}>
          <button
            type="button"
            className="btn-secondary"
            style={styles.cancelBtn}
            onClick={onCancel}
            disabled={loading}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            style={{ ...styles.confirmBtn, ...(danger ? styles.confirmBtnDanger : {}) }}
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? '…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

const styles = {
  backdrop: {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0,0,0,0.4)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
    padding: '1rem',
  },
  box: {
    background: 'var(--surface)',
    borderRadius: 'var(--radius)',
    border: '1px solid var(--border)',
    boxShadow: 'var(--shadow-hover)',
    padding: '1.5rem',
    maxWidth: 400,
    width: '100%',
  },
  title: { margin: '0 0 0.5rem 0', fontSize: '1.1rem', fontWeight: 600 },
  message: { margin: '0 0 1.25rem 0', color: 'var(--text-muted)', lineHeight: 1.5, fontSize: '0.95rem' },
  actions: { display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' },
  cancelBtn: {},
  confirmBtn: { background: 'var(--accent)', color: 'var(--accent-text)' },
  confirmBtnDanger: { background: 'var(--danger)', color: '#fff' },
}
