import { Link } from 'react-router-dom'

const STEP = ({ num, title, children }) => (
  <div style={styles.step}>
    <span style={styles.stepNum}>{num}</span>
    <div>
      <h3 style={styles.stepTitle}>{title}</h3>
      {children}
    </div>
  </div>
)

const Card = ({ title, children }) => (
  <div style={styles.card}>
    <h3 style={styles.cardTitle}>{title}</h3>
    {children}
  </div>
)

export default function Docs() {
  return (
    <div className="main-content" style={styles.wrapper}>
      <h1 style={styles.h1}>Documentation</h1>
      <p style={styles.lead}>
        ForSight runs external pentest phases from a checklist. Upload scope (ROE), run Recon on domains, Nmap on IPs, then Enumeration and Web host tools. Download workpapers from the Reporting tab.
      </p>

      <section style={styles.section}>
        <h2 style={styles.h2}>Quick start</h2>
        <div style={styles.steps}>
          <STEP num="1" title="Create a project">
            <p style={styles.p}>From the home page, enter a name and click <strong>Create</strong> (or use <strong>+ New engagement</strong> in the sidebar).</p>
          </STEP>
          <STEP num="2" title="Upload or paste ROE">
            <p style={styles.p}>In the project, upload a .txt, .csv, or .json file with IPs and/or domains (one per line), or paste into the text area and click <strong>Save as ROE</strong>. This is your scope. You can view and edit targets in the <strong>Current targets</strong> panel on the right.</p>
          </STEP>
          <STEP num="3" title="Run Recon (optional)">
            <p style={styles.p}>In the <strong>Checklist</strong> tab, expand <strong>Recon</strong>. Run subfinder, dnsrecon, amass, theHarvester, WHOIS, etc. These use <strong>domains only</strong> and do not require Nmap.</p>
          </STEP>
          <STEP num="4" title="Run Nmap">
            <p style={styles.p}>Expand <strong>Nmap</strong>. Run <strong>TCP top 5000 ports</strong> (and optionally <strong>Service fingerprint (-sV)</strong>). Enumeration and Web host tabs stay disabled until Nmap has run — they use Nmap results for ports.</p>
          </STEP>
          <STEP num="5" title="Run Enumeration & Web host">
            <p style={styles.p}>After Nmap finishes, expand <strong>Enumeration</strong> and <strong>Web host</strong>. Run SSL/TLS, legacy protocols, Nuclei, Nikto, Gowitness, etc. They target ports discovered by Nmap.</p>
          </STEP>
          <STEP num="6" title="View results & download">
            <p style={styles.p}>Use the <strong>Jobs</strong> tab for job status and live output; <strong>Hosts</strong> for per-host ports, screenshots, and findings. Use the <strong>Reporting</strong> tab to download all tool outputs as a zip.</p>
          </STEP>
        </div>
      </section>

      <section style={styles.section}>
        <h2 style={styles.h2}>Workflow summary</h2>
        <div style={styles.workflowBox}>
          <p style={styles.workflowP}>
            Upload/paste ROE (IPs + domains). Run <strong>Recon/OSINT on domains only</strong>. Run <strong>Nmap on ROE IPs</strong> — Enumeration and Web host use Nmap results for their ports. Download workpapers from the <strong>Reporting</strong> tab.
          </p>
        </div>
      </section>

      <section style={styles.section}>
        <h2 style={styles.h2}>Checklist phases</h2>
        <div style={styles.grid}>
          <Card title="Pre-engagement"><p style={styles.cardP}>Scope and communication. No runnable tools.</p></Card>
          <Card title="Recon"><p style={styles.cardP}>Subfinder, dnsrecon, amass, theHarvester, WHOIS, CloudEnum. Domains only; no Nmap.</p></Card>
          <Card title="Nmap"><p style={styles.cardP}>TCP top 5000 + service fingerprint. Run before Enumeration and Web host.</p></Card>
          <Card title="Enumeration"><p style={styles.cardP}>SSL/TLS, legacy (SNMP, FTP, SMB, LDAP), email. Requires Nmap.</p></Card>
          <Card title="Web host"><p style={styles.cardP}>Nuclei, Nikto, Gowitness, CMS. Requires Nmap.</p></Card>
          <Card title="Exploitation"><p style={styles.cardP}>Password spray (run manually).</p></Card>
        </div>
      </section>

      <section style={styles.section}>
        <h2 style={styles.h2}>Project tabs</h2>
        <ul style={styles.ul}>
          <li><strong>Checklist</strong> — Phases and tasks; run individual tools or Run all per phase.</li>
          <li><strong>Jobs</strong> — Status and live output for each scan job.</li>
          <li><strong>Hosts</strong> — Per-host summary: ports, Gowitness screenshots, Nuclei findings (grouped by port).</li>
          <li><strong>Reporting</strong> — Download all tool outputs (workpapers) as a zip.</li>
        </ul>
      </section>

      <section style={styles.section}>
        <h2 style={styles.h2}>Other</h2>
        <ul style={styles.ul}>
          <li><strong>Delete project</strong> — From the engagements list or inside a project (header). Confirm before deletion; removes project, jobs, and result files.</li>
          <li><strong>Targets</strong> — The right-hand panel shows current IPs and domains. Use <strong>Edit targets</strong> to change the list; this updates the same store all tools use.</li>
          <li><Link to="/roadmap">Roadmap</Link> — Planned features. <Link to="/feedback">Feedback</Link> — Submit feature requests or bugs.</li>
          <li><Link to="/settings">Settings</Link> — Appearance (light/dark mode), about, and project/targets tips. Theme can also be toggled from the header (top right).</li>
        </ul>
      </section>
    </div>
  )
}

const styles = {
  wrapper: { maxWidth: 680, margin: '0 auto', paddingBottom: '2rem' },
  h1: { margin: '0 0 0.5rem 0', fontSize: '1.5rem', fontWeight: 700 },
  lead: { fontSize: '0.95rem', color: 'var(--text-muted)', marginBottom: '2rem', lineHeight: 1.6 },
  section: { marginBottom: '2.5rem' },
  h2: { margin: '0 0 1rem 0', fontSize: '1.1rem', fontWeight: 600 },
  p: { margin: 0, lineHeight: 1.55, fontSize: '0.9rem' },
  ul: { margin: 0, paddingLeft: '1.25rem', lineHeight: 1.7, fontSize: '0.9rem' },
  code: { background: 'var(--bg)', padding: '0.1rem 0.35rem', borderRadius: 'var(--radius)', fontFamily: 'var(--font-mono)', fontSize: '0.85em' },
  steps: { display: 'flex', flexDirection: 'column', gap: '1.25rem' },
  step: { display: 'flex', gap: '1rem', alignItems: 'flex-start' },
  stepNum: {
    flexShrink: 0,
    width: 28,
    height: 28,
    borderRadius: '50%',
    background: 'var(--accent)',
    color: 'var(--accent-text)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '0.85rem',
    fontWeight: 700,
  },
  stepTitle: { margin: '0 0 0.35rem 0', fontSize: '1rem', fontWeight: 600 },
  workflowBox: { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1rem 1.25rem' },
  workflowP: { margin: 0, lineHeight: 1.6, fontSize: '0.9rem', color: 'var(--text)' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.75rem' },
  card: { background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '0.75rem 1rem' },
  cardTitle: { margin: '0 0 0.35rem 0', fontSize: '0.9rem', fontWeight: 600 },
  cardP: { margin: 0, fontSize: '0.85rem', lineHeight: 1.5, color: 'var(--text-muted)' },
}
