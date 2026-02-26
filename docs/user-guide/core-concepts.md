# Core Concepts

Understand the main ideas behind ForSight: projects, ROE, the checklist, and how data flows.

---

## Projects

A **project** is one engagement or assessment. Everything in ForSight is scoped to a project:

- **ROE / targets** — The list of IPs and hostnames in scope.
- **Checklist** — Phased progress (Pre-engagement, Recon, Nmap, Enumeration, Web host, Exploitation, Reporting).
- **Jobs** — Individual scan runs (e.g. one Nmap job, one Nuclei job).
- **Hosts** — Aggregated list of hosts discovered, with ports, screenshots, and findings.
- **Nessus** — Scans and imported results tied to the project.

You create a project from the dashboard, then open it to work with ROE, the checklist, hosts, and Nessus.

---

## ROE (Rules of Engagement) / Targets

**ROE** in ForSight means **target list**: the IP addresses and hostnames that are in scope for the engagement. This list is used by:

- Nmap and other scanners (what to scan).
- Nuclei, Nikto, Dirb, Gowitness (which hosts to hit).
- Nessus (targets can be passed when creating or launching scans).

You can:

- **Upload** a file (one target per line, or comma-separated).
- **Paste** text into the ROE area.
- **Edit** the list in the UI (add/remove IPs or hostnames).

Targets are stored per project. Always set ROE before running broad scans.

---

## Checklist phases

The checklist is a **phased workflow** for an external pentest:

| Phase | Purpose |
|-------|--------|
| **Pre-engagement** | Scope and communication (no automated runners). |
| **Recon** | Subfinder, DNS recon, Amass, theHarvester, WHOIS, etc. |
| **Nmap** | TCP ports, service fingerprinting. **Required** before Enumeration and Web host in many flows. |
| **Enumeration** | SSL/TLS, SNMP, FTP, SMB, LDAP, banners, email security. |
| **Web host** | Nuclei, Nikto, Dirb, Gowitness, CMS scanners. |
| **Exploitation** | Placeholder for manual work (e.g. password spray via Burp). |
| **Reporting** | Download workpapers and finalize. |

Each phase has **runners** (individual tools). You run a phase or a single runner; output is streamed to the job view and stored under the project’s results directory.

---

## Jobs

A **job** is a single execution of a runner (e.g. one Nmap scan, one Nuclei run). Jobs:

- Are tied to a project.
- Show live output in the UI.
- Can be stopped from the UI.
- Persist output under `backend/data/results/<project_id>/`.

The **Checklist** tab lists phases and runners; clicking run starts a job. The **Jobs** area (or job list in the project) shows status and output.

---

## Hosts aggregation

ForSight **aggregates discovered hosts** from:

- Nmap (hosts and ports).
- Gowitness (screenshots).
- Nuclei (findings per host).
- Nessus imports (findings per host, when you import a scan).

The **Hosts** tab shows one row per host, with ports, screenshots, and findings. You can **exclude** hosts (e.g. out-of-scope) so they don’t clutter the view or reports.

---

## Nessus

ForSight can talk to **Tenable/Nessus** (API and optionally the web UI):

- **API** — List scans, create scans, launch by ID, export, import results.
- **Web (Selenium)** — Launch by scan name (finds the row in My Scans, clicks launch), create scan via UI, delete (trash).

Imported Nessus results are stored per project and merged into the **Hosts** view as Nessus findings. You can also view findings by vulnerability (table + detail) and by host.

---

## Data flow (summary)

1. **Project** → has **ROE (targets)** and **checklist**.
2. You **run runners** → **jobs** produce output files in `results/<project_id>/`.
3. **Hosts aggregator** reads Nmap, Gowitness, Nuclei, Nessus imports → **Hosts** tab.
4. **Nessus** (optional): create/launch/import → findings appear in Hosts and Nessus views.
5. **Reporting** → download workpapers zip from the project.
