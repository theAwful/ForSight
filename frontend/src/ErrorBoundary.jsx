import { Component } from 'react'
import { Link } from 'react-router-dom'

/** Catches render errors in project/detail pages so we show a fallback instead of a blank screen. */
export default class ErrorBoundary extends Component {
  state = { hasError: false, error: null }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    console.error('ErrorBoundary caught:', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={styles.wrapper}>
          <h2 style={styles.title}>Something went wrong</h2>
          <p style={styles.msg}>
            This page couldn’t load. You can go back to engagements and try again.
          </p>
          <Link to="/" style={styles.link}>Back to engagements</Link>
        </div>
      )
    }
    return this.props.children
  }
}

const styles = {
  wrapper: { padding: '2rem', color: 'var(--text)' },
  title: { margin: '0 0 0.5rem 0', fontSize: '1.25rem' },
  msg: { color: 'var(--text-muted)', margin: '0 0 1rem 0' },
  link: {
    display: 'inline-block',
    padding: '0.5rem 1rem',
    background: 'var(--accent)',
    color: 'var(--accent-text)',
    borderRadius: 'var(--radius)',
    textDecoration: 'none',
    fontWeight: 500,
  },
}
