/**
 * SeverityBadge
 *
 * Renders a colored severity pill for Nessus/Nuclei findings.
 *
 * Props:
 *   severity  'critical'|'high'|'medium'|'low'|'info'|'none'|number(0-4)
 *   count     number  — optional, appended as "(N)" to the label
 *   size      'sm'|'md'  — default 'md'
 */
const SEVERITY_MAP = {
  4: 'critical',
  3: 'high',
  2: 'medium',
  1: 'low',
  0: 'info',
}

const LABELS = {
  critical: 'Critical',
  high:     'High',
  medium:   'Medium',
  low:      'Low',
  info:     'Info',
  none:     'None',
}

export default function SeverityBadge({ severity, count, size = 'md' }) {
  // Normalise numeric → string
  const key = (typeof severity === 'number')
    ? (SEVERITY_MAP[severity] || 'info')
    : (String(severity || 'none').toLowerCase())

  const label = LABELS[key] || key

  const sm = size === 'sm'
  const style = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '3px',
    padding: sm ? '2px 7px' : '3px 10px',
    borderRadius: 'var(--radius-full)',
    fontSize: sm ? '0.7rem' : '0.75rem',
    fontFamily: 'var(--font-mono)',
    fontWeight: 600,
    letterSpacing: '0.04em',
    whiteSpace: 'nowrap',
    ...severityStyle(key),
  }

  return (
    <span style={style} title={label}>
      {label}
      {count !== undefined && (
        <span style={{ opacity: count === 0 ? 0.5 : 1 }}> ({count})</span>
      )}
    </span>
  )
}

function severityStyle(key) {
  switch (key) {
    case 'critical': return { background: '#3d1a1c', color: 'var(--color-critical)', border: '1px solid #6e2226' }
    case 'high':     return { background: '#2d1a1c', color: 'var(--color-high)',     border: '1px solid #5a1a1c' }
    case 'medium':   return { background: '#2d2010', color: 'var(--color-warning)',  border: '1px solid #5a3e10' }
    case 'low':      return { background: '#0d1f38', color: 'var(--color-low)',      border: '1px solid #1a3a6e' }
    case 'info':     return { background: 'var(--color-bg-elevated)', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border)' }
    default:         return { background: 'transparent', color: 'var(--color-text-disabled)', border: 'none' }
  }
}
