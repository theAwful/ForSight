# Deployment

Run ForSight in production or a shared environment.

---

## Publishing the docs (Gitea) {#publishing-the-docs-gitea}

The documentation is built with **MkDocs Material**. To publish it (e.g. on Gitea or any static host):

1. **Install the Material theme** (use a venv so you don't hit “externally-managed-environment”). From the repo root:
   ```bash
   cd ForSight
   python3 -m venv .venv-docs
   source .venv-docs/bin/activate   # Windows: .venv-docs\Scripts\activate
   pip install -r docs/requirements.txt
   ```
2. **Build the static site** — use the venv’s `mkdocs` so it sees the Material theme:
   ```bash
   # Option A: activate venv, then run mkdocs
   source .venv-docs/bin/activate
   mkdocs build

   # Option B: use the helper script (no need to activate)
   ./build-docs.sh
   ```
   To preview: `mkdocs serve` (with venv active) or `./build-docs.sh serve`.  
   Output is in the `site/` directory.

3. **Publish the `site/` folder:**
   - **Gitea Pages:** If your Gitea instance has Pages enabled, push the contents of `site/` to a branch (e.g. `pages`) or use your instance’s preferred method (see your Gitea admin docs).
   - **Any static host:** Upload `site/` to nginx, Apache, Netlify, or any static hosting; serve the root as the site root.

4. **Optional:** In `mkdocs.yml` at the repo root, set `site_url`, `repo_url`, `repo_name`, and `edit_uri` to your Gitea repo and docs URL so the “Edit” link and repo icon point to your Gitea instance.

---

## Docker (recommended)

Use Docker Compose for a single-command stack:

```bash
docker compose build --network=host   # if build needs DNS
docker compose up -d
```

- Set **FORSIGHT_SECRET_KEY** (and optionally **FORSIGHT_DEFAULT_PASSWORD_HASH**) via environment or `.env`.
- Data lives in the `forsight_data` volume; back it up if you need to preserve DB and results.
- For production, use HTTPS in front of the app (reverse proxy) and set **FORSIGHT_CORS_ORIGINS** to your frontend origin.

---

## Local / VM

1. **Backend:** Python 3.10+, venv, `pip install -r backend/requirements.txt`, set env (see [Configuration](reference/configuration.md)), run `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
2. **Frontend:** Node 18+, `npm install` and `npm run build` in `frontend/`; serve the `frontend/dist/` directory with nginx or another web server.
3. Point the frontend to the backend API URL (env or build-time).
4. Install required tools (nmap, nuclei, etc.) on the host or in a custom image.

---

## Security checklist

- Set a strong **FORSIGHT_SECRET_KEY**.
- Change default password (e.g. **FORSIGHT_DEFAULT_PASSWORD_HASH** with a bcrypt hash).
- Use HTTPS and restrict CORS (**FORSIGHT_CORS_ORIGINS**).
- Restrict network access to the backend and Nessus/API credentials.
- Back up `backend/data/` (DB and results) regularly if the data is important.
