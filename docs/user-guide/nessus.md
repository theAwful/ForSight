# Nessus Integration

Use Tenable/Nessus from ForSight: list scans, create scans, launch via web, import results, and view findings.

---

## Configuration

ForSight needs at least one of:

- **API keys** — `FORSIGHT_TENABLE_ACCESS_KEY` and `FORSIGHT_TENABLE_SECRET_KEY` (Tenable.io or Nessus API).
- **Web login** — `FORSIGHT_TENABLE_USERNAME` and `FORSIGHT_TENABLE_PASSWORD` for “launch via web” and “create/delete via web”.

Set **FORSIGHT_TENABLE_BASE_URL** (e.g. `https://nessus.example.com:8834`) for Nessus Pro. Optional: **FORSIGHT_TENABLE_VERIFY_SSL** (default false for self-signed).

---

## Nessus tab

Inside a project, the **Nessus** tab provides:

- **Scan list** — Scans from the Tenable/Nessus API (name, status, last run).
- **Launch (via web)** — Selenium opens My Scans, finds the row by **scan name**, reads the row’s **data-id**, then clicks the glyphicon launch button `<i data-id="..." class="glyphicons launch ...">` for that scan. No API launch; the browser does the click.
- **Create scan (API)** — Create a scan via API (template, name, targets from project ROE).
- **Create via web** — Selenium: New Scan → template (e.g. Advanced) → name and targets → Save.
- **Import results** — Export from Nessus (API), wait for file, download and parse; results are stored and merged into **Hosts** and the Nessus findings views.
- **Trash** — Delete scan via web (Selenium: find row by name, click trash, confirm).

---

## Launch by name

Because the scan ID may not be known until the scan exists in Nessus, **Launch (via web)** works by **scan name**:

1. You click **Launch (via web)** for a row in the scan list (the row name is sent).
2. Backend opens My Scans, finds the table row with that name (e.g. `tr` with `data-name` or `td.scan-visible-name`).
3. Reads **data-id** from that row (the scan id).
4. Finds the launch icon `i.glyphicons.launch[data-id="..."]` and clicks it.

So the correct scan is launched without needing the numeric ID in the UI.

---

## Import results

1. Run a scan in Nessus (via ForSight or manually).
2. In ForSight, click **Import results** for that scan.
3. Backend requests an export (Nessus format), polls until ready, downloads the file, parses it, and stores the result under the project (e.g. `nessus_imports.json`).
4. **Hosts** aggregator merges Nessus findings per host; the **Nessus** tab shows findings by vuln and by host (description, solution, output, plugin details).

---

## Findings UI

- **By vulnerability** — Table: severity, name, count; search and severity summary; click a vuln for full detail (description, solution, output, plugin sidebar).
- **By host** — List of hosts with Nessus findings; click a host for the same detail layout plus host-level info.

“Open in Nessus” links out to the Nessus UI when the base URL is configured.
