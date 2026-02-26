# Reporting

Export workpapers and scan outputs from a project.

---

## Workpapers zip

ForSight can **download a zip** of “workpapers” — the scan output and result files for the project (e.g. job logs, Nmap output, Nuclei JSON, screenshots, Nessus-related data). Use this for:

- Archiving engagement output.
- Attaching evidence to a report.
- Handoff to another analyst.

Location in the UI is typically under the project (e.g. **Reporting** phase or a **Download workpapers** / **Export** button). The backend zips contents of `backend/data/results/<project_id>/` (and related assets) and returns the file.

---

## What’s included

The exact contents depend on what the backend packs; typically:

- Job output files (`job_*.txt`, `nmap_ports.txt`, `nmap_services.txt`, etc.).
- Nuclei and other JSON/text results.
- Screenshots (e.g. from Gowitness).
- Nessus import data or references (if configured).

Check the Reporting section in the app or the API (e.g. workpapers/download endpoint) for the precise list.
