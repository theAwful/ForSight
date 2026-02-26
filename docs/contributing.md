# Contributing

Contributions to ForSight are welcome.

---

## Development setup

1. Clone the repo from your Gitea instance: `git clone https://your-gitea-server/youruser/ForSight.git`
2. Backend: `cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
3. Frontend: `cd frontend && npm install && npm run dev`
4. Run backend: `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`
5. Optional: copy `.env.example` to `.env` and set keys (e.g. Tenable, secret key).

---

## Documentation

Docs are built with **Material for MkDocs** (same style as [KrakenHashes](https://zerkereod.github.io/krakenhashes/latest/user-guide/)).

- Edit sources under `docs/`.
- Config: `mkdocs.yml`.
- Serve locally: `pip install mkdocs-material && mkdocs serve`
- Build: `mkdocs build` (output in `site/`).

---

## Reporting issues

Open an issue in the Gitea repository with:

- What you did
- What you expected
- What happened (errors, logs)
- Environment (Docker vs local, OS, versions)

---

## License

MIT — see `LICENSE` in the repo root.
