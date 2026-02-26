# Hosts & Findings

View aggregated hosts, ports, screenshots, and vulnerability findings.

---

## Hosts tab

The **Hosts** tab for a project shows one row per discovered host, with:

- **Host** — IP or hostname (canonical).
- **Ports** — From Nmap (and any other runners that write port data).
- **Screenshots** — From Gowitness (thumbnails or links).
- **Findings** — Nuclei and Nessus (when imported) findings tied to that host.

Data is aggregated from:

- Nmap output (hosts, ports, services).
- Gowitness (screenshots per URL).
- Nuclei JSON output.
- Nessus import (per-host findings from imported scan results).

---

## Excluding hosts

You can **exclude** a host (e.g. out-of-scope or false positive). Excluded hosts:

- Are hidden from the main Hosts list (or shown as excluded depending on UI).
- Don’t clutter reporting or counts.

Use the exclude action from the host row or a bulk action if the UI offers it. Exclusions are stored per project.

---

## Findings detail

- Clicking a **finding** (Nuclei or Nessus) can open a detail panel: description, severity, remediation, output, etc.
- **Nessus** findings can be viewed by vulnerability (table with severity, name, count) or by host; same layout applies (description, solution, output, plugin details).

See [Nessus Integration](nessus.md) for how imported Nessus data appears in Hosts and in the Nessus tab.
