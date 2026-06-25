# ForSight

**External penetration testing platform** — manage engagements from Rules of Engagement through recon, enumeration, vulnerability scanning, and workpaper delivery.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)
![React](https://img.shields.io/badge/React-18-61dafb)

---

## What it does

ForSight gives penetration testers a single interface to run an external engagement end-to-end. Define your scope, work through a phased checklist, let the tool runners execute and stream output back to you, review aggregated findings per host, and export workpapers when you're done.

It is not a scanner. It orchestrates the scanners you already have.

---

## Features

**Engagement management**
- Define Rules of Engagement (ROE) with IPs and domains per project
- Multiple simultaneous engagements, each fully isolated
- Session-based auth with configurable credentials

**Phased checklist**
- Pre-engagement → Recon → Nmap → Enumeration → Web → Exploitation → Reporting
- Progress tracking per phase with live output streaming
- Manual checklist items alongside automated runners

**Tool orchestration**

| Phase | Tools |
|---|---|
| Recon | subfinder, dnsrecon, Amass, theHarvester, WHOIS, cloud_enum, DeHashed |
| Nmap | TCP top ports, full TCP, service fingerprint, UDP |
| Enumeration | testssl, sslscan, SNMP, FTP, SMB, LDAP, banner grabbing, email security |
| Web | Nuclei, Nikto, Dirb, Gowitness, WPScan, droopescan, CMSeek |

**Hosts view**
- Aggregated per-host findings across all scan types
- Open ports table, screenshots, Nuclei findings, and Nessus findings per host
- Tabbed interface — no scrolling through mixed data
- Remove out-of-scope hosts from the list

**Nessus Pro integration**
- Create, launch, pause, stop, and delete scans from within ForSight
- Import scan results and browse findings by severity or host
- Full vuln detail with CVE links, CVSS scores, plugin output, and solution

**DeHashed integration**
- Query leaked credential data per domain during recon
- Results saved to workpapers automatically

**Reporting**
- Download all scan outputs as a zip workpapers archive

---

## Quick start — Docker (recommended)

```bash
git clone https://github.com/theAwful/ForSight.git
cd ForSight
docker compose up -d
```

> If the build fails with `Temporary failure resolving 'deb.debian.org'`, your build environment has no DNS. Use:
> ```bash
> docker compose build --network=host
> docker compose up -d
> ```

- **App:** http://localhost
- **Default login:** `forsight` / `forsight`
- Data persists in the `forsight_data` Docker volume across restarts

To stop: `docker compose down`  
To rebuild after code changes: `docker compose up -d --build`

---

## Quick start — Local

### Requirements

- Python 3.10+
- Node 18+
- Tools on `PATH` as needed: `nmap`, `subfinder`, `dnsrecon`, `amass`, `theHarvester`, `whois`, `testssl.sh`, `sslscan`, `nuclei`, `nikto`, `dirb`, `gowitness`, `wpscan`, `droopescan`, `cloud_enum`

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

- App: http://localhost:5173
- API docs: http://localhost:8000/docs

---

## Configuration

All configuration is via environment variables with the `FORSIGHT_` prefix, or a `.env` file in the `backend/` directory.

### Core

| Variable | Default | Description |
|---|---|---|
| `FORSIGHT_SECRET_KEY` | `change-me` | Session signing key — set this in production |
| `FORSIGHT_DEFAULT_USERNAME` | `forsight` | Login username |
| `FORSIGHT_DEFAULT_PASSWORD_HASH` | — | Bcrypt hash to replace the default password |
| `FORSIGHT_DATA_DIR` | `data` | Base directory for DB, uploads, and results |

### Tool paths

Override any tool path if it is not on `PATH`:

```
FORSIGHT_NMAP_PATH=/usr/bin/nmap
FORSIGHT_NUCLEI_PATH=/usr/local/bin/nuclei
FORSIGHT_GOWITNESS_PATH=/usr/local/bin/gowitness
# etc.
```

### Nessus Pro

| Variable | Description |
|---|---|
| `FORSIGHT_TENABLE_BASE_URL` | Nessus URL — default `https://127.0.0.1:8834` |
| `FORSIGHT_TENABLE_ACCESS_KEY` | API access key (Settings → My Account → API Keys) |
| `FORSIGHT_TENABLE_SECRET_KEY` | API secret key |
| `FORSIGHT_TENABLE_USERNAME` | Username for browser automation (scan create/launch/delete) |
| `FORSIGHT_TENABLE_PASSWORD` | Password for browser automation |
| `FORSIGHT_TENABLE_VERIFY_SSL` | `false` to skip SSL verification (default for self-signed Nessus cert) |

### DeHashed

| Variable | Description |
|---|---|
| `FORSIGHT_DEHASHED_KEY` | DeHashed API key — recon leaked creds step runs automatically when set |

---

## Project layout

```
ForSight/
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI entrypoint, lifespan, routes
│   │   ├── config.py             # pydantic-settings configuration
│   │   ├── auth.py               # Session auth
│   │   ├── checklist.py          # Phase/item definitions and job dispatch
│   │   ├── hosts_aggregator.py   # Merges scan outputs into per-host records
│   │   ├── nessus_web_launch.py  # Selenium automation for Nessus Pro
│   │   └── runners/              # One module per tool/phase
│   │       ├── recon.py          # subfinder, dnsrecon, amass, theHarvester, whois, cloud, dehashed
│   │       ├── nmap.py
│   │       ├── ssl.py
│   │       ├── legacy.py         # SNMP, FTP, SMB, LDAP, banners
│   │       ├── web.py            # Nuclei, Nikto, Dirb, Gowitness
│   │       └── cms.py            # WPScan, droopescan, CMSeek
│   ├── data/                     # SQLite DB, results, uploads (gitignored in production)
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.jsx               # Router and auth shell
│       ├── Layout.jsx            # Sidebar and page shell
│       ├── ProjectDetail.jsx     # Engagement detail with tab navigation
│       ├── Checklist.jsx         # Phased checklist with live job output
│       ├── Hosts.jsx             # Per-host findings with tabbed detail
│       ├── Nessus.jsx            # Nessus scan management and results browser
│       └── index.css             # Design tokens and global styles
├── docker-compose.yml
└── README.md
```

---

## Checklist phases

| # | Phase | What runs |
|---|---|---|
| 1 | Pre-engagement | Manual items only — scope confirmation, kickoff, comms |
| 2 | Recon | subfinder, dnsrecon, Amass, theHarvester, WHOIS, cloud_enum, DeHashed |
| 3 | Nmap | TCP top 1000, full TCP, service/version detection |
| 4 | Enumeration | SSL/TLS, SNMP, FTP, SMB, LDAP, banner grabbing, email security (SPF/DKIM/DMARC) |
| 5 | Web | Nuclei, Nikto, Dirb, Gowitness screenshots, CMS detection |
| 6 | Exploitation | Manual — password spray, Burp, credential testing |
| 7 | Reporting | Download workpapers zip |

---

## Nessus integration notes

ForSight uses the Nessus Pro API for importing results and the Nessus web UI (via browser automation) for creating, launching, pausing, stopping, and deleting scans. This is necessary because Nessus Pro removed scan creation from its API in recent versions.

Selenium and Chrome must be installed in the backend environment for browser automation to work. The Docker image handles this automatically.

A persistent browser session is maintained in the background to avoid login overhead on every action. The session is refreshed automatically every 20 minutes.

---

## Security notes

- Change `FORSIGHT_SECRET_KEY` before any non-local deployment
- The default `forsight`/`forsight` credentials are for local use only — set `FORSIGHT_DEFAULT_PASSWORD_HASH` in production
- Nessus credentials are stored in `.env` in plaintext — secure the file accordingly
- ForSight is designed to run on a private pentest VM or jump host, not exposed to the internet

---

## License

MIT — see [LICENSE](LICENSE)
