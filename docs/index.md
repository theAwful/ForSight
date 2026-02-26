# ForSight

**External penetration testing checklist & tool wrapper** — a web app that orchestrates external pentests from ROE (Rules of Engagement) through recon, enumeration, web checks, Nessus integration, and reporting.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

---

## What is ForSight?

ForSight is a **full-stack security assessment app**: FastAPI backend and React frontend with SQLite, orchestrating Nmap, Nuclei, Nessus, and other tools while aggregating host and vulnerability findings per project.

- **ROE-driven scope** — Upload or paste IPs and domains; edit targets per engagement.
- **Phased checklist** — Pre-engagement → Recon → Nmap → Enumeration → Web host → Exploitation → Reporting.
- **Tool orchestration** — Subfinder, DNS recon, Amass, theHarvester, Nmap, Nuclei, Nikto, Dirb, Gowitness, Nessus, and more; output streamed to the UI.
- **Hosts view** — Aggregated hosts with ports, screenshots, Nuclei and Nessus findings; exclude out-of-scope hosts.
- **Nessus** — Create scans, launch via web (Selenium), import results, view findings by host/vuln.
- **Reporting** — Download workpapers (scan outputs) as a zip.

---

## Quick Navigation

### New Users

1. Start with [Getting Started](getting-started.md) to run ForSight (Docker or local).
2. Read [Core Concepts](user-guide/core-concepts.md) to understand projects, ROE, and the checklist.
3. Create your first project and run jobs with [Checklist & Jobs](user-guide/checklist-and-jobs.md).

### Common Tasks

- Create a project and upload ROE (targets)
- Run a phase (e.g. Nmap, Nuclei) from the checklist
- View aggregated hosts and findings
- Configure and use Nessus (import, launch via web)
- Download workpapers / reporting zip

### Advanced Topics

- [Nessus Integration](user-guide/nessus.md) — API vs web launch, import, findings UI
- [Configuration](reference/configuration.md) — Environment variables, tool paths
- [Deployment](deployment.md) — Docker, production tips

---

## Best Practices

!!! tip "Pro tips"
    - Upload ROE (targets) before running Nmap or web scans so scope is clear.
    - Run Nmap first when the checklist requires it; Enumeration and Web host phases depend on it.
    - Use Nessus “Import results” after a scan to see findings in ForSight alongside Nuclei/hosts.
    - Exclude out-of-scope hosts from the Hosts tab so they don’t clutter reports.

---

## Getting Support

- Review the [Troubleshooting](user-guide/troubleshooting.md) guide.
- Open an issue in your Gitea repository.
- Check the [API docs](http://localhost:8000/docs) when running the backend.
