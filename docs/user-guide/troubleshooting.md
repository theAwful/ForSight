# Troubleshooting

Common issues and how to resolve them.

---

## Login / auth

- **Default credentials** — `forsight` / `forsight`. Change in production via `FORSIGHT_DEFAULT_PASSWORD_HASH` and env.
- **Session** — Backend uses session cookies. If you get 401, log in again; check that `FORSIGHT_SECRET_KEY` is set in production.

---

## Docker build fails (DNS)

- **Symptom:** “Temporary failure resolving 'deb.debian.org'” (or similar).
- **Fix:** Build with host network so the build can resolve packages:  
  `docker compose build --network=host`  
  Then: `docker compose up -d`.

---

## Jobs fail or “command not found”

- **Symptom:** A runner fails with “command not found” or similar.
- **Cause:** The tool (e.g. `nuclei`, `subfinder`) isn’t on the backend’s `PATH`.
- **Fix:** Install the tool in the container or on the host where the backend runs. Override path with `FORSIGHT_<TOOL>_PATH` if supported (see [Configuration](../reference/configuration.md)).

---

## Nessus “not configured”

- **Symptom:** Nessus tab says API or web launch not configured.
- **Fix:** Set Tenable API keys and/or username/password and base URL in env (see [Nessus Integration](nessus.md) and [Configuration](../reference/configuration.md)).

---

## Launch via web fails (stacktrace in UI)

- **Symptom:** After clicking “Create via web” or “Launch (via web)” you see a long stacktrace (e.g. Chrome/Selenium crash).
- **Fix:** The backend now sanitizes those errors and shows a short message. Ensure Selenium and Chrome/Chromium are installed where the backend runs; try “Create scan (API)” or create/launch the scan directly in Nessus and use Import in ForSight.

---

## Hosts or findings missing

- **Nmap:** Run the Nmap phase so that port/host data exists under the project’s results.
- **Nuclei:** Run the Nuclei runner; the aggregator expects the Nuclei JSON output in the project results directory.
- **Nessus:** Use **Import results** for the scan; until import completes, Nessus findings won’t appear in Hosts or the Nessus findings views.

---

## CORS errors

- **Symptom:** Browser shows CORS errors when calling the API.
- **Fix:** Backend CORS is configured for the frontend origin. Set `FORSIGHT_CORS_ORIGINS` if you’re using a different origin (e.g. custom domain or port).
