# API

ForSight’s backend is a **FastAPI** app. When the backend is running, interactive API docs are available at:

- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc` (if enabled)

---

## Base URL

All API routes are under `/api` (e.g. `POST /api/auth/login`, `GET /api/projects`). The frontend is configured to talk to the backend (e.g. `http://localhost:8000` in dev, or same host in Docker).

---

## Auth

- **Login:** `POST /api/auth/login` with `username` and `password` (JSON). Sets session cookie.
- **Logout:** `POST /api/auth/logout`.
- **Current user:** `GET /api/auth/me`.

Most project and scan endpoints require an authenticated session.

---

## Main areas

| Area | Examples |
|------|----------|
| **Projects** | `GET/POST /api/projects`, `GET /api/projects/{id}`, `GET /api/projects/{id}/targets` |
| **ROE** | `POST /api/projects/{id}/roe`, `POST /api/projects/{id}/roe/paste` |
| **Checklist** | `GET /api/checklist`, `GET /api/projects/{id}/checklist` |
| **Jobs** | `POST /api/projects/{id}/run/{runner_key}`, `GET /api/projects/{id}/jobs`, `GET /api/projects/{id}/jobs/{job_id}/output` |
| **Hosts** | `GET /api/projects/{id}/hosts`, `POST /api/projects/{id}/hosts/exclude` |
| **Nessus** | `GET /api/projects/{id}/nessus/scans`, `POST /api/projects/{id}/nessus/launch-web`, `POST /api/projects/{id}/nessus/imports`, etc. |
| **Health** | `GET /api/health` |

For full route list, request/response schemas, and try-it-out, use **http://localhost:8000/docs**.
