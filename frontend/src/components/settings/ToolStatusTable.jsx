import { useState, useCallback } from 'react'

const SHELL_METACHAR_RE = /[;&|`$<>()\n\r'"\\]/

/**
 * ToolStatusTable
 *
 * Displays all configured pentesting tools with their binary path,
 * version string, and health status badge. Supports inline path editing.
 *
 * Props:
 *   tools        ToolStatus[]  — from GET /api/tools/status
 *   onRefresh    () => void
 *   onUpdatePath (key, path) => Promise<void>
 *   isLoading    boolean
 *   isRefreshing boolean
 *   error        string | null
 */
export default function ToolStatusTable({ tools = [], onRefresh, onUpdatePath, isLoading, isRefreshing, error }) {
  const [editingKey, setEditingKey] = useState(null)
  const [editPath, setEditPath] = useState('')
  const [savingKey, setSavingKey] = useState(null)
  const [saveError, setSaveError] = useState('')

  const startEdit = useCallback((tool) => {
    setEditingKey(tool.key)
    setEditPath(tool.configured_path || '')
    setSaveError('')
  }, [])

  const cancelEdit = useCallback(() => {
    setEditingKey(null)
    setEditPath('')
    setSaveError('')
  }, [])

  const handleSave = async (key) => {
    const trimmed = editPath.trim()
    if (!trimmed) {
      setSaveError('Path cannot be empty.')
      return
    }
    if (SHELL_METACHAR_RE.test(trimmed)) {
      setSaveError('Path must be a plain file path — no shell metacharacters.')
      return
    }
    setSavingKey(key)
    setSaveError('')
    try {
      await onUpdatePath(key, trimmed)
      setEditingKey(null)
    } catch (err) {
      setSaveError(err?.message || 'Failed to update path.')
    } finally {
      setSavingKey(null)
    }
  }

  if (isLoading) {
    return <SkeletonTable />
  }

  if (error) {
    return (
      <div style={styles.errorCallout}>
        <span style={{ color: 'var(--color-danger)' }}>⚠</span>
        {' '}Failed to load tool status. Check backend connection.
        <button type="button" onClick={onRefresh} style={styles.retryLink}>Retry</button>
      </div>
    )
  }

  if (!tools.length) {
    return (
      <div style={styles.emptyMsg}>
        No tools configured. Check <code style={styles.code}>backend/app/config.py</code>.
      </div>
    )
  }

  return (
    <div style={styles.tableWrap}>
      <table style={styles.table}>
        <thead>
          <tr style={styles.thead}>
            <th style={{ ...styles.th, width: '20%' }}>Tool</th>
            <th style={{ ...styles.th, width: '35%' }}>Configured Path</th>
            <th style={{ ...styles.th, width: '22%' }}>Version</th>
            <th style={{ ...styles.th, width: '11%' }}>Status</th>
            <th style={{ ...styles.th, width: '12%' }}>Action</th>
          </tr>
        </thead>
        <tbody>
          {tools.map((tool, idx) => (
            <>
              <tr
                key={tool.key}
                style={{
                  ...styles.tr,
                  background: idx % 2 === 0 ? 'var(--color-bg-surface)' : 'var(--color-bg-primary)',
                }}
              >
                {/* Tool name */}
                <td style={styles.td}>
                  <span style={styles.toolName}>{tool.display_name}</span>
                  <span style={styles.toolKey}>{tool.key}</span>
                </td>

                {/* Configured path */}
                <td style={styles.td}>
                  <span
                    style={{
                      ...styles.mono,
                      color: tool.status === 'not_found' ? 'var(--color-danger)' : 'var(--color-text-secondary)',
                    }}
                    title={tool.resolved_path || tool.configured_path}
                  >
                    {tool.configured_path}
                  </span>
                  {tool.resolved_path && tool.resolved_path !== tool.configured_path && (
                    <span style={styles.resolvedPath} title="Resolved binary location">
                      → {tool.resolved_path}
                    </span>
                  )}
                </td>

                {/* Version */}
                <td style={styles.td}>
                  {tool.version_string ? (
                    <span style={styles.mono} title={tool.version_string}>
                      {tool.version_string.length > 40
                        ? tool.version_string.slice(0, 40) + '…'
                        : tool.version_string}
                    </span>
                  ) : tool.version_error ? (
                    <span style={{ ...styles.mono, color: 'var(--color-warning)' }} title={tool.version_error}>
                      {tool.version_error.length > 40 ? tool.version_error.slice(0, 40) + '…' : tool.version_error}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--color-text-disabled)' }}>—</span>
                  )}
                </td>

                {/* Status badge */}
                <td style={styles.td}>
                  <StatusBadge status={tool.status} />
                </td>

                {/* Action */}
                <td style={styles.td}>
                  <button
                    type="button"
                    onClick={() => editingKey === tool.key ? cancelEdit() : startEdit(tool)}
                    style={styles.editBtn}
                  >
                    {editingKey === tool.key ? 'Cancel' : tool.status === 'not_found' ? 'Set path' : 'Edit path'}
                  </button>
                </td>
              </tr>

              {/* Inline edit row */}
              {editingKey === tool.key && (
                <tr key={`${tool.key}-edit`} style={styles.editRow}>
                  <td colSpan={5} style={styles.editCell}>
                    <div style={styles.editForm}>
                      <input
                        type="text"
                        value={editPath}
                        onChange={(e) => setEditPath(e.target.value)}
                        placeholder="/usr/bin/nmap"
                        style={styles.editInput}
                        autoFocus
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleSave(tool.key)
                          if (e.key === 'Escape') cancelEdit()
                        }}
                        aria-label={`New path for ${tool.display_name}`}
                      />
                      <button
                        type="button"
                        onClick={() => handleSave(tool.key)}
                        disabled={savingKey === tool.key}
                        style={styles.saveBtn}
                      >
                        {savingKey === tool.key ? 'Saving…' : 'Save'}
                      </button>
                      <button
                        type="button"
                        onClick={cancelEdit}
                        style={styles.cancelBtn}
                      >
                        Cancel
                      </button>
                    </div>
                    {saveError && (
                      <div style={styles.saveError}>{saveError}</div>
                    )}
                    <div style={styles.persistNote}>
                      ℹ This change is temporary. To persist across restarts, set{' '}
                      <code style={styles.code}>
                        FORSIGHT_{tool.key.toUpperCase()}_PATH
                      </code>{' '}
                      in your <code style={styles.code}>.env</code> file.
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function StatusBadge({ status }) {
  const cfg = {
    found:     { label: 'Found',     bg: 'rgba(63,185,80,0.12)',  color: 'var(--color-success)', border: 'rgba(63,185,80,0.3)' },
    not_found: { label: 'Not Found', bg: 'rgba(248,81,73,0.12)',  color: 'var(--color-danger)',  border: 'rgba(248,81,73,0.3)' },
    error:     { label: 'Error',     bg: 'rgba(210,153,34,0.12)', color: 'var(--color-warning)', border: 'rgba(210,153,34,0.3)' },
  }[status] || { label: status, bg: 'transparent', color: 'var(--color-text-secondary)', border: 'var(--color-border)' }

  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 'var(--radius-full)',
      fontSize: '0.7rem',
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      letterSpacing: '0.04em',
      background: cfg.bg,
      color: cfg.color,
      border: `1px solid ${cfg.border}`,
    }}>
      {cfg.label}
    </span>
  )
}

function SkeletonTable() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '4px 0' }}>
      {[1, 2, 3, 4, 5].map((i) => (
        <div key={i} style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div className="skeleton" style={{ height: '16px', width: '15%', borderRadius: '3px' }} />
          <div className="skeleton" style={{ height: '16px', width: '30%', borderRadius: '3px' }} />
          <div className="skeleton" style={{ height: '16px', width: '20%', borderRadius: '3px' }} />
          <div className="skeleton" style={{ height: '16px', width: '10%', borderRadius: '3px' }} />
          <div className="skeleton" style={{ height: '16px', width: '10%', borderRadius: '3px' }} />
        </div>
      ))}
    </div>
  )
}

const styles = {
  tableWrap: {
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-lg)',
    overflow: 'hidden',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
  },
  thead: {
    background: 'var(--color-bg-elevated)',
    borderBottom: '1px solid var(--color-border)',
  },
  th: {
    padding: '10px 14px',
    textAlign: 'left',
    fontSize: '0.7rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: 'var(--color-text-secondary)',
  },
  tr: {
    borderBottom: '1px solid var(--color-border)',
    transition: 'background 0.1s',
  },
  td: {
    padding: '10px 14px',
    verticalAlign: 'middle',
  },
  toolName: {
    display: 'block',
    fontSize: '0.85rem',
    fontWeight: 600,
    color: 'var(--color-text-primary)',
  },
  toolKey: {
    display: 'block',
    fontSize: '0.7rem',
    color: 'var(--color-text-disabled)',
    fontFamily: 'var(--font-mono)',
  },
  mono: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.75rem',
  },
  resolvedPath: {
    display: 'block',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.68rem',
    color: 'var(--color-text-disabled)',
    marginTop: '2px',
  },
  editBtn: {
    background: 'none',
    border: 'none',
    color: 'var(--color-accent)',
    fontSize: '0.78rem',
    cursor: 'pointer',
    padding: '0',
    textDecoration: 'underline',
    textUnderlineOffset: '2px',
  },
  editRow: {
    background: 'var(--color-bg-elevated)',
    borderBottom: '1px solid var(--color-border)',
  },
  editCell: {
    padding: '12px 14px',
  },
  editForm: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  editInput: {
    flex: 1,
    minWidth: '200px',
    background: 'var(--color-bg-primary)',
    border: '1px solid var(--color-border-strong)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--color-text-primary)',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.85rem',
    padding: '6px 10px',
    outline: 'none',
  },
  saveBtn: {
    padding: '5px 14px',
    background: 'var(--color-accent)',
    color: '#fff',
    border: 'none',
    borderRadius: 'var(--radius-sm)',
    fontSize: '0.8rem',
    cursor: 'pointer',
    fontWeight: 500,
  },
  cancelBtn: {
    padding: '5px 12px',
    background: 'transparent',
    color: 'var(--color-text-secondary)',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)',
    fontSize: '0.8rem',
    cursor: 'pointer',
  },
  saveError: {
    marginTop: '6px',
    fontSize: '0.78rem',
    color: 'var(--color-danger)',
  },
  persistNote: {
    marginTop: '8px',
    fontSize: '0.75rem',
    color: 'var(--color-text-disabled)',
  },
  errorCallout: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    background: 'rgba(248,81,73,0.08)',
    border: '1px solid var(--color-danger)',
    borderRadius: 'var(--radius-md)',
    padding: '12px 16px',
    fontSize: '0.85rem',
    color: 'var(--color-text-primary)',
  },
  retryLink: {
    background: 'none',
    border: 'none',
    color: 'var(--color-accent)',
    cursor: 'pointer',
    fontSize: '0.85rem',
    textDecoration: 'underline',
    padding: '0 4px',
  },
  emptyMsg: {
    padding: '20px',
    textAlign: 'center',
    fontSize: '0.85rem',
    color: 'var(--color-text-secondary)',
  },
  code: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8em',
    background: 'var(--color-bg-elevated)',
    padding: '1px 5px',
    borderRadius: '3px',
  },
}
