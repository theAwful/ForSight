# Project layout

High-level layout of the ForSight repository.

| Path | Description |
|------|-------------|
| `backend/` | FastAPI app: auth, projects, ROE/targets, checklist, jobs, runners, hosts aggregation, Nessus. |
| `backend/app/` | Core app: `main.py`, `config.py`, `auth.py`, `checklist.py`, `hosts_aggregator.py`, `nessus_parse.py`, `nessus_web_launch.py`, `tenable_client.py`, `runners/`. |
| `backend/data/` | SQLite DB (`forsight.db`), uploads, `results/<project_id>/` (job output, screenshots, Nessus imports). Repo may include demo data. |
| `frontend/` | Vite + React UI: login, projects, checklist, jobs, hosts, Nessus tab, reporting. |
| `docs/` | MkDocs Material documentation (this site). |
| `mkdocs.yml` | MkDocs and Material theme config. |
| `docker-compose.yml` | Runs backend (with tools) + frontend (nginx); single command to spin up. |
| `backend/docs/TOOLS.md` | How tools are wired and how to add or swap them (if present). |

---

## Serving the docs

From the repo root:

```bash
pip install mkdocs-material
mkdocs serve
```

Then open **http://127.0.0.1:8001** (use `-a 127.0.0.1:8001` to avoid conflicting with the backend on 8000).

Build static site:

```bash
mkdocs build
```

Output is in `site/`. You can deploy that to **Gitea Pages** (if your Gitea instance has it), or any static host (nginx, Netlify, etc.). See [Deployment → Publishing the docs](../deployment.md#publishing-the-docs-gitea).
