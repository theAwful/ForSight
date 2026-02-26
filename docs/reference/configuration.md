# Configuration

Backend uses **pydantic-settings** with env prefix `FORSIGHT_` and optional `.env` in the backend directory.

---

## Auth

| Variable | Description |
|----------|-------------|
| `FORSIGHT_SECRET_KEY` | Session signing key; **required in production** (e.g. `openssl rand -hex 32`). |
| `FORSIGHT_DEFAULT_USERNAME` | Login username (default `forsight`). |
| `FORSIGHT_DEFAULT_PASSWORD_HASH` | Bcrypt hash to override the default password. |

---

## Paths

| Variable | Description |
|----------|-------------|
| `FORSIGHT_DATA_DIR` | Base data directory (default `data`). |
| `FORSIGHT_UPLOADS_DIR` | Uploads (default under `data/uploads`). |
| `FORSIGHT_RESULTS_DIR` | Scan results per project (default `data/results`). |

---

## Tool paths

Override if the binary is not on `PATH` or has a different name:

| Variable | Default |
|----------|---------|
| `FORSIGHT_NMAP_PATH` | `nmap` |
| `FORSIGHT_SUBFINDER_PATH` | `subfinder` |
| `FORSIGHT_NUCLEI_PATH` | `nuclei` |
| `FORSIGHT_NIKTO_PATH` | `nikto` |
| `FORSIGHT_DIRB_PATH` | `dirb` |
| `FORSIGHT_GOWITNESS_PATH` | `gowitness` |
| `FORSIGHT_DNSRECON_PATH` | `dnsrecon` |
| `FORSIGHT_AMASS_PATH` | `amass` |
| `FORSIGHT_THEHARVESTER_PATH` | `theHarvester` |
| `FORSIGHT_WHOIS_PATH` | `whois` |
| `FORSIGHT_TESTSSL_PATH` | `testssl.sh` |
| `FORSIGHT_SSLSCAN_PATH` | `sslscan` |
| `FORSIGHT_MASSCAN_PATH` | `masscan` |
| `FORSIGHT_WPSCAN_PATH` | `wpscan` |
| `FORSIGHT_DROOPESCAN_PATH` | `droopescan` |
| `FORSIGHT_CLOUDENUM_PATH` | `cloud_enum` |

Optional: `FORSIGHT_DIRB_WORDLIST` — path to wordlist for Dirb (default uses repo wordlist if present).

---

## Nessus / Tenable

| Variable | Description |
|----------|-------------|
| `FORSIGHT_TENABLE_BASE_URL` | Nessus/Tenable base URL (default `https://127.0.0.1:8834`). Tenable.io: `https://cloud.tenable.com`. |
| `FORSIGHT_TENABLE_ACCESS_KEY` | API access key (Tenable.io or Nessus API keys). |
| `FORSIGHT_TENABLE_SECRET_KEY` | API secret key. |
| `FORSIGHT_TENABLE_USERNAME` | Username for session login (needed for “launch via web”, “create via web”, “delete via web”). |
| `FORSIGHT_TENABLE_PASSWORD` | Password for session login. |
| `FORSIGHT_TENABLE_VERIFY_SSL` | Set `true` to verify TLS; `false` for self-signed (e.g. local Nessus). |

---

## CORS

| Variable | Description |
|----------|-------------|
| `FORSIGHT_CORS_ORIGINS` | Comma-separated extra origins (e.g. `https://app.example.com`). Defaults include localhost:5173, 3000, 8080. |

---

## Other

| Variable | Description |
|----------|-------------|
| `FORSIGHT_DEBUG` | Set for debug mode. |
| `FORSIGHT_APP_NAME` | App name (default `ForSight`). |
