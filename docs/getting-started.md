# Getting Started

Run ForSight with **Docker** (recommended) or **locally** with Python and Node.

---

## Quick start (Docker)

Easiest way to run ForSight — backend (with common tools) and frontend in one go:

```bash
git clone https://your-gitea-server/youruser/ForSight.git
cd ForSight
docker compose up -d
```

If the build fails with **"Temporary failure resolving 'deb.debian.org'"**, the build sandbox has no DNS. Use the host network so the image can fetch packages:

```bash
docker compose build --network=host
docker compose up -d
```

| What | Where |
|------|--------|
| **App** | http://localhost (port 80) |
| **Login** | `forsight` / `forsight` |

- Data (DB, uploads, results) is stored in the Docker volume `forsight_data` and persists across restarts.
- Optional: set `FORSIGHT_SECRET_KEY` in a `.env` file before `docker compose up`.

To stop: `docker compose down`. To rebuild after code changes: `docker compose up -d --build`.

---

## Quick start (local)

### Prerequisites

- **Python 3.10+** (backend)
- **Node 18+** (frontend)
- Pentesting tools on `PATH` as needed: `nmap`, `subfinder`, `nuclei`, `nikto`, `dirb`, `gowitness`, etc.

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

| What | Where |
|------|--------|
| **App** | http://localhost:5173 |
| **API docs** | http://localhost:8000/docs |

Default login: **forsight** / **forsight**.

---

## Next steps

1. [Core Concepts](user-guide/core-concepts.md) — Projects, ROE, checklist phases.
2. [Projects & ROE](user-guide/projects-and-roe.md) — Create a project and upload targets.
3. [Checklist & Jobs](user-guide/checklist-and-jobs.md) — Run scans and view output.
