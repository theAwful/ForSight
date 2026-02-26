# Projects & ROE

Create engagements and define scope with targets (ROE).

---

## Creating a project

1. From the **dashboard**, click **New project** (or the equivalent action).
2. Enter a **name** (e.g. client name or engagement code).
3. Save. The new project appears in the list; open it to work with ROE, checklist, hosts, and Nessus.

Projects are stored in the SQLite database. All subsequent data (ROE, jobs, results, Nessus imports) is scoped to the project ID.

---

## Adding ROE (targets)

**ROE** in ForSight is your **target list**: IPs and hostnames that are in scope.

### Upload a file

1. Open the project and go to the **ROE / targets** section.
2. Use **Upload** and select a text file with one target per line (or comma-separated).
3. The backend parses IPs and hostnames and saves them as the project’s targets.

### Paste targets

1. In the same ROE area, use **Paste** (or the text area provided).
2. Paste a list of IPs and/or hostnames (one per line or comma-separated).
3. Submit. Targets are merged or replaced according to the UI (e.g. “Replace” or “Merge”).

### Editing targets

- Use the project’s ROE/targets view to add or remove individual IPs or hostnames.
- These targets are used when you run Nmap, Nuclei, Nessus, and other scanners so scope stays consistent.

---

## API summary

| Action | Endpoint / idea |
|--------|------------------|
| Create project | `POST /api/projects` with `{ "name": "..." }` |
| List projects | `GET /api/projects` |
| Upload ROE | `POST /api/projects/{id}/roe` (file) |
| Paste ROE | `POST /api/projects/{id}/roe/paste` (body with pasted text) |
| Get targets | `GET /api/projects/{id}/targets` |

Targets are returned as IPs and domains (or combined list) for use by runners and Nessus.
