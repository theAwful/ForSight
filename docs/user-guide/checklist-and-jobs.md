# Checklist & Jobs

Run phased scans and view job output.

---

## Using the checklist

1. Open a **project** and go to the **Checklist** tab.
2. You’ll see **phases** (Pre-engagement, Recon, Nmap, Enumeration, Web host, Exploitation, Reporting).
3. Each phase has **runners** (e.g. Nmap, Nuclei, Nikto). Expand a phase to see them.
4. **Run** a whole phase or a single runner. A **job** is created and output streams in the UI.

Progress is tracked per phase (e.g. completed runners). Some phases depend on others (e.g. Nmap before Web host) so the UI may guide order.

---

## Jobs

- **Jobs** are individual scan executions (one runner run).
- From the project you can open a **Jobs** list and click a job to see **live output** and status.
- Use **Stop** to cancel a running job (if the runner supports it).

Job output is stored under `backend/data/results/<project_id>/` (e.g. `job_31.txt`, `nmap_ports.txt`). The **Hosts** aggregator and reporting use these files.

---

## Runners (overview)

| Phase | Examples |
|-------|----------|
| Recon | Subfinder, dnsrecon, Amass, theHarvester, WHOIS |
| Nmap | TCP top ports, service detection |
| Enumeration | SSL/TLS, SNMP, FTP, SMB, LDAP, banners |
| Web host | Nuclei, Nikto, Dirb, Gowitness, CMS (wpscan, droopescan) |
| Exploitation | Manual (e.g. Burp password spray) |
| Reporting | Download workpapers zip |

Tool paths can be overridden via [Configuration](../reference/configuration.md). If a tool isn’t installed (e.g. in Docker), that runner may fail until the tool is available.

---

## Viewing job output

- In the job detail view, output is streamed as the job runs.
- You can also open the result files under `backend/data/results/<project_id>/` (e.g. `job_*.txt`, `nmap_ports.txt`, `web_nuclei.json`).
