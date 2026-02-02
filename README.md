# ForSight

**External penetration testing checklist & tool wrapper** — a web app that orchestrates external pentests from ROE (Rules of Engagement) through recon, enumeration, web checks, and reporting.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Features

- **ROE-driven scope** — Upload or paste IPs and domains; edit targets per engagement.
- **Phased checklist** — Pre-engagement → Recon → Nmap → Enumeration → Web host → Exploitation → Reporting, with progress bars and collapsible sections.
- **Tool orchestration** — Runs subfinder, dnsrecon, Amass, theHarvester, WHOIS, Nmap, testssl/sslscan, SNMP/FTP/SMB/LDAP checks, Nuclei, Nikto, Dirb, Gowitness, CMS scanners, and more; output streamed to the UI.
- **Hosts view** — Aggregated hosts with ports, screenshots (Gowitness), and Nuclei findings; remove out-of-scope hosts from the list.
- **Auth** — Session-based login (default `forsight` / `forsight`; override in production).
- **Reporting** — Download workpapers (scan outputs) as a zip.

---

## Quick start

### Prerequisites

- **Python 3.10+** (backend)
- **Node 18+** (frontend)
- Pentesting tools on `PATH` as needed: `nmap`, `subfinder`, `dnsrecon`, `amass`, `theHarvester`, `whois`, `testssl.sh`, `sslscan`, `nuclei`, `nikto`, `dirb`, `gowitness`, `wpscan`, `droopescan`, etc.

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Optional: copy `.env.example` to `.env` and set `FORSIGHT_SECRET_KEY` and `FORSIGHT_DEFAULT_PASSWORD_HASH` for production.

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

- **App:** http://localhost:5173  
- **API docs:** http://localhost:8000/docs  

Default login: **forsight** / **forsight**.

---

## Project layout

| Path | Description |
|------|-------------|
| `backend/` | FastAPI app: auth, projects, ROE/targets, checklist, jobs, runners (recon, nmap, ssl, legacy, web, CMS), hosts aggregation |
| `backend/app/` | Core app: `main.py`, `config.py`, `auth.py`, `checklist.py`, `hosts_aggregator.py`, `runners/` |
| `backend/data/` | SQLite DB, uploads, results per project, wordlists. This repo includes **demo data** for presentation; remove or replace for production. |
| `frontend/` | Vite + React UI: login, engagements, checklist, jobs, hosts, reporting, settings |
| `backend/docs/TOOLS.md` | How tools are wired and how to add or swap them |

---

## Configuration

Backend uses **pydantic-settings** with env prefix `FORSIGHT_` and optional `.env`:

| Variable | Description |
|----------|-------------|
| `FORSIGHT_SECRET_KEY` | Session signing key (required in production) |
| `FORSIGHT_DEFAULT_USERNAME` | Login username (default `forsight`) |
| `FORSIGHT_DEFAULT_PASSWORD_HASH` | Bcrypt hash to override default password |
| `FORSIGHT_DATA_DIR` | Base data directory (default `data`) |
| `FORSIGHT_*_PATH` | Tool paths (e.g. `FORSIGHT_NMAP_PATH`, `FORSIGHT_DIRB_PATH`) |

---

## Checklist phases (summary)

1. **Pre-engagement** — Scope and communication (no runners).
2. **Recon** — Subfinder, dnsrecon, Amass, theHarvester, WHOIS, cloud enum, leaked creds.
3. **Nmap** — TCP top ports, service fingerprint; required before Enumeration and Web host.
4. **Enumeration** — SSL/TLS, legacy (Nmap, SNMP, FTP, SMB, banners, LDAP), email security.
5. **Web host** — Nuclei, Nikto, Dirb, Gowitness, CMS (wpscan, droopescan, CMSeek).
6. **Exploitation** — Password spray (manual/Burp).
7. **Reporting** — Download workpapers zip.

---

## License

MIT — see [LICENSE](LICENSE).
