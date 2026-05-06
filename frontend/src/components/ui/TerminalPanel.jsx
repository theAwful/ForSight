import { useEffect, useRef, useState, useCallback } from 'react'

const MAX_LINES_DEFAULT = 10_000

/**
 * TerminalPanel
 *
 * Displays tool output in a dark monospace panel with:
 * - Auto-scroll-to-bottom while live (suspends when user scrolls up)
 * - "↓ Jump to bottom" button when auto-scroll is suspended
 * - Line-count truncation warning when output exceeds maxLines
 * - Copy-to-clipboard button
 * - LIVE pulsing badge when isLive=true
 * - Strips basic ANSI escape codes before display
 *
 * Props:
 *   text        string   — full output text to display
 *   isLive      boolean  — show LIVE badge and auto-scroll (default false)
 *   maxLines    number   — truncate to last N lines (default 10000)
 *   className   string   — additional CSS class
 */
export default function TerminalPanel({ text = '', isLive = false, maxLines = MAX_LINES_DEFAULT, className = '' }) {
  const containerRef = useRef(null)
  const [userScrolled, setUserScrolled] = useState(false)
  const [copied, setCopied] = useState(false)
  const scrollThreshold = 20

  // Strip ANSI escape codes
  const stripped = (text || '').replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')

  // Truncate to last maxLines
  const lines = stripped.split('\n')
  const truncated = lines.length > maxLines
  const displayLines = truncated ? lines.slice(lines.length - maxLines) : lines
  const displayText = displayLines.join('\n')

  // Auto-scroll logic
  const scrollToBottom = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    el.scrollTop = el.scrollHeight
  }, [])

  // Detect manual scroll-up
  const handleScroll = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    const distFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight
    if (distFromBottom > scrollThreshold) {
      setUserScrolled(true)
    } else {
      setUserScrolled(false)
    }
  }, [])

  // Auto-scroll on text change when live and user hasn't scrolled up
  useEffect(() => {
    if (isLive && !userScrolled) {
      scrollToBottom()
    }
  }, [displayText, isLive, userScrolled, scrollToBottom])

  const handleJumpToBottom = () => {
    setUserScrolled(false)
    scrollToBottom()
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text || '')
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard not available in some contexts
    }
  }

  const isEmpty = !stripped.trim()

  return (
    <div
      style={{
        position: 'relative',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
      className={className}
    >
      {/* Truncation warning */}
      {truncated && (
        <div style={styles.truncationBanner}>
          ⚠ Showing last {maxLines.toLocaleString()} lines of {lines.length.toLocaleString()} total
        </div>
      )}

      {/* Terminal container */}
      <div
        ref={containerRef}
        role="log"
        aria-label="Tool output"
        aria-live={isLive ? 'polite' : undefined}
        onScroll={handleScroll}
        style={styles.terminal}
      >
        {/* Top-right badges */}
        <div style={styles.topRight}>
          {isLive && (
            <span style={styles.liveBadge} aria-label="Live output">
              ● LIVE
            </span>
          )}
          <button
            type="button"
            onClick={handleCopy}
            style={styles.copyBtn}
            title={copied ? 'Copied!' : 'Copy output'}
            aria-label="Copy output to clipboard"
          >
            {copied ? '✓' : '⎘'}
          </button>
        </div>

        {isEmpty ? (
          <span style={styles.emptyText}>No output yet.</span>
        ) : (
          <pre style={styles.pre}>{displayText}</pre>
        )}
      </div>

      {/* Jump to bottom button */}
      {isLive && userScrolled && (
        <button
          type="button"
          onClick={handleJumpToBottom}
          style={styles.jumpBtn}
          aria-label="Jump to bottom of output"
        >
          ↓ Jump to bottom
        </button>
      )}
    </div>
  )
}

const styles = {
  truncationBanner: {
    background: '#2d2010',
    borderBottom: '1px solid var(--color-warning)',
    color: 'var(--color-warning)',
    fontSize: '0.75rem',
    padding: '6px 16px',
    borderRadius: 'var(--radius-sm) var(--radius-sm) 0 0',
    fontFamily: 'var(--font-mono)',
  },
  terminal: {
    position: 'relative',
    width: '100%',
    minHeight: '200px',
    maxHeight: '600px',
    overflowY: 'auto',
    background: 'var(--color-bg-terminal)',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-md)',
    padding: '16px',
    scrollbarWidth: 'thin',
    scrollbarColor: 'var(--color-border) transparent',
  },
  topRight: {
    position: 'absolute',
    top: '8px',
    right: '8px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    zIndex: 2,
  },
  liveBadge: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.7rem',
    color: 'var(--color-success)',
    animation: 'live-pulse 1.5s ease-in-out infinite',
    letterSpacing: '0.05em',
  },
  copyBtn: {
    width: '28px',
    height: '28px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'var(--color-bg-elevated)',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--color-text-secondary)',
    cursor: 'pointer',
    fontSize: '0.85rem',
    transition: 'color 0.15s, border-color 0.15s',
  },
  pre: {
    margin: 0,
    padding: 0,
    fontFamily: 'var(--font-mono)',
    fontSize: '0.75rem',
    lineHeight: 1.6,
    color: 'var(--color-text-primary)',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
  },
  emptyText: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8rem',
    color: 'var(--color-text-disabled)',
  },
  jumpBtn: {
    position: 'absolute',
    bottom: '12px',
    right: '12px',
    background: 'var(--color-accent)',
    color: '#fff',
    border: 'none',
    borderRadius: 'var(--radius-full)',
    padding: '5px 12px',
    fontSize: '0.75rem',
    fontFamily: 'var(--font-mono)',
    cursor: 'pointer',
    zIndex: 3,
    boxShadow: '0 2px 8px rgba(0,0,0,0.4)',
  },
}
