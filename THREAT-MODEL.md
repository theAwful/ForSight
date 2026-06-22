| Field | Value |
|---|---|
| **Document Title** | Threat Model — ForSight External Pentest Orchestration Platform |
| **Version** | 1.0 |
| **Date** | June 2026 |
---

## 1. Executive Summary

This document applies the STRIDE methodology to identify, categorise, and prioritise threats across the authentication layer, API surface, tool-runner subprocess engine, data-at-rest and data-in-transit, and the containerised deployment model. Eighteen distinct threats were identified: four Critical, five High, five Medium, and four Low severity findings.

---

## 2. System Overview

### 2.1 Architecture

ForSight follows a two-tier containerised architecture:

- **Backend** — FastAPI application (Python 3.10+) running under Uvicorn, exposed internally on port 8000. Provides REST endpoints for authentication, project/target management, checklist state, job execution, hosts aggregation, and reporting.
- **Frontend** — React (Vite) single-page application compiled to static assets and served by nginx. nginx also acts as a TLS-terminating reverse proxy, forwarding API calls to the backend on port 8000 via the internal Docker network.
- **Database** — SQLite file stored in the `forsight_data` Docker volume, co-located with scan output files, uploaded ROE documents, and wordlists.
- **Tool runners** — The backend spawns system subprocesses (via Python `subprocess`) to invoke installed penetration-testing tools. Output is streamed back to the frontend via SSE (Server-Sent Events) or polled job endpoints.

### 2.2 Data Flows

| # | Flow |
|---|---|
| DF-1 | Analyst browser → nginx (HTTPS/443) → FastAPI backend (HTTP/8000) — all authenticated API calls |
| DF-2 | FastAPI backend → host OS subprocess — tool invocation carrying target hostnames/IPs derived from user-supplied ROE |
| DF-3 | FastAPI backend → SQLite (file I/O) — project state persistence, scan metadata, hosts aggregation |
| DF-4 | FastAPI backend → Docker volume filesystem — raw scan output, uploaded files, workpapers zip |
| DF-5 | FastAPI backend → network (outbound) — tool-generated traffic to target scope |

### 2.3 Trust Boundaries

| ID | Boundary |
|---|---|
| TB-1 | Browser / Internet ↔ nginx TLS endpoint |
| TB-2 | nginx ↔ FastAPI backend (Docker internal network) |
| TB-3 | FastAPI backend ↔ host OS / subprocess environment |
| TB-4 | Docker volume ↔ FastAPI backend (filesystem access) |

### 2.4 Key Assumptions

- ForSight is deployed in a private/LAN environment accessible only to the pentest team, not exposed to the public internet.
- The default credentials (`forsight` / `forsight`) are the starting state; production deployment requires overriding them via environment variables.
- The application is single-tenant: all authenticated users share equal privileges.
- Demo engagement data is committed to the public repository and must be removed before production use.

---

## 3. Threat Actors

| Actor | Motivation | Notes |
|---|---|---|
| External Attacker | Data theft, credential harvest, pivot to engagement targets | Targets the web interface if exposed; exploits default credentials or unpatched CVEs |
| Malicious Insider | Exfiltration of client engagement data, sabotage | Authenticated user abusing tool-runner capabilities for SSRF or local file access |
| Pentest Target (Counter-attack) | Detect / disrupt the pentest, false-flag injection | A hostile target could serve crafted tool output designed to exploit parsing weaknesses |
| Supply-Chain Adversary | Code injection into open-source tool dependencies | npm, PyPI, or OS package compromise in Docker image build |

---

## 4. STRIDE Threat Register

Likelihood and Impact are rated Low / Medium / High. Severity is derived from the combination. All ratings assume the default out-of-the-box configuration.

### 4.1 Spoofing

| ID | Threat | Component | Likelihood | Impact | Severity | Mitigation |
|---|---|---|---|---|---|---|
| S-01 | Authentication bypass via default credentials (`forsight`/`forsight` hardcoded in README; no lockout, no MFA) | Auth / Session | High | High | 🔴 Critical | Override credentials via env vars before deployment; add account lockout; enforce MFA or IP allow-listing |
| S-02 | Session token prediction or theft due to weak or default `FORSIGHT_SECRET_KEY` (`change-me-in-production`) | Session signing | High | High | 🔴 Critical | Mandate strong random secret key; rotate on each deployment; verify cookie Secure/HttpOnly/SameSite flags |
| S-03 | Cookie replay / session fixation if HTTPS-only flag not enforced (`FORSIGHT_SESSION_HTTPS_ONLY` defaults true but can be overridden) | Auth / TLS | Medium | High | 🟠 High | Never disable `FORSIGHT_SESSION_HTTPS_ONLY`; validate Secure cookie attribute in integration tests |

### 4.2 Tampering

| ID | Threat | Component | Likelihood | Impact | Severity | Mitigation |
|---|---|---|---|---|---|---|
| T-01 | Command injection via unsanitised target input passed to subprocess tool runners (e.g. nmap, subfinder, nikto) | Tool Runners | High | High | 🔴 Critical | Validate all targets against strict allowlist (IP regex / RFC 1123 hostname); use subprocess list form, never `shell=True`; sandbox with seccomp/AppArmor |
| T-02 | Path traversal in file download (workpapers zip); attacker supplies `../etc/passwd` as filename component | Reporting / File I/O | Medium | High | 🟡 Medium | Canonicalise all user-supplied paths; assert resolved path is within `FORSIGHT_DATA_DIR` before `open()` |
| T-03 | Tampering with SQLite DB file via Docker volume mount if host permissions are overly broad | Database | Low | High | 🟢 Low | Set volume to read-only for non-backend processes; validate DB integrity on startup; consider PostgreSQL for multi-user hardening |
| T-04 | Malicious scan output injection: target returns crafted tool output that manipulates parser or hosts aggregator logic | Hosts Aggregator | Medium | Medium | 🟡 Medium | Treat all subprocess stdout as untrusted; sanitise before rendering in frontend; use structured output formats where tools support them |

### 4.3 Repudiation

| ID | Threat | Component | Likelihood | Impact | Severity | Mitigation |
|---|---|---|---|---|---|---|
| R-01 | No audit log of who ran which tool against which target; operator actions are unattributable if credentials are shared | Auth / Logging | High | Medium | 🟠 High | Implement per-action audit log (timestamp, user, action, target); persist to append-only log outside the SQLite DB |
| R-02 | Scan outputs stored without integrity metadata; evidence could be altered post-collection without detection | Data / Reporting | Low | Medium | 🟢 Low | Compute and store SHA-256 digest of each scan output file at write time; verify on workpapers packaging |

### 4.4 Information Disclosure

| ID | Threat | Component | Likelihood | Impact | Severity | Mitigation |
|---|---|---|---|---|---|---|
| I-01 | Demo engagement data committed to the public GitHub repository leaks historical client target information | Repository / Data | High | High | 🔴 Critical | Remove demo data immediately; add `backend/data/` to `.gitignore`; scan git history with trufflehog/git-secrets |
| I-02 | FastAPI `/docs` (Swagger UI) and `/redoc` endpoints exposed by default; full API schema visible without authentication | API | High | Medium | 🟠 High | Disable `/docs` and `/redoc` in production (`app.openapi_url = None`); or gate behind auth middleware |
| I-03 | Verbose error messages and stack traces returned to the client expose internal paths, library versions, and query structure | API Error Handling | Medium | Medium | 🟡 Medium | Set `debug=False` in production; implement generic error handler returning opaque error IDs; log detail server-side only |
| I-04 | Scan output files (containing client target data) accessible to any authenticated user regardless of project ownership (flat auth model) | Auth / Multi-tenancy | Low | Medium | 🟢 Low | Enforce project-scoped access control on all file and job endpoints; validate user-to-project association on every request |

### 4.5 Denial of Service

| ID | Threat | Component | Likelihood | Impact | Severity | Mitigation |
|---|---|---|---|---|---|---|
| D-01 | Authenticated requests spawn unbounded subprocesses (nmap, masscan) exhausting CPU/memory | Tool Runners / API | Medium | High | 🟠 High | Enforce per-user job concurrency limit; add API rate limiting (slowapi/Starlette middleware); implement job queue with worker pool cap |
| D-02 | Large file upload or crafted scan output fills the Docker volume causing backend failure and data loss | File I/O / Volume | Low | Medium | 🟢 Low | Set upload size limits in FastAPI; configure Docker volume with size quota; monitor disk usage in health endpoint |

### 4.6 Elevation of Privilege

| ID | Threat | Component | Likelihood | Impact | Severity | Mitigation |
|---|---|---|---|---|---|---|
| E-01 | Backend container likely runs as root; successful command injection gives full container root, enabling Docker socket escape if mounted | Container / Runners | Medium | High | 🟠 High | Run backend as non-root user (`USER 1001` in Dockerfile); drop all Linux capabilities; do not mount Docker socket; use seccomp profile |
| E-02 | SSRF: tool runner accepts arbitrary IPs including RFC 1918 / link-local ranges, enabling access to cloud metadata endpoints (`169.254.169.254`) | Tool Runners | Medium | High | 🟠 High | Block RFC 1918, link-local, and loopback ranges in scope validation; use network policy / egress filter on backend container |
| E-03 | Supply chain: a compromised PyPI or npm package in `requirements.txt` / `package.json` installs malicious code at build time | Build / Dependencies | Low | High | 🟡 Medium | Pin all dependencies to exact versions; use `pip-audit` and `npm audit` in CI; verify package hashes |

---

## 5. Prioritised Findings Summary

| Ref | Finding | Risk | Recommendation |
|---|---|---|---|
| S-01 | Default hardcoded credentials with no lockout | 🔴 Critical | Require credential override at startup; enforce lockout after N failures; consider TOTP MFA |
| S-02 | Weak default session signing key | 🔴 Critical | Generate cryptographically random 32+ byte key; fail-fast on startup if key equals the placeholder |
| T-01 | Command injection via target input to tool runners | 🔴 Critical | Strict allowlist validation; subprocess list API; seccomp sandbox |
| I-01 | Demo client data committed to public repository | 🔴 Critical | Remove data, purge git history, add to `.gitignore`, scan with trufflehog |
| I-02 | Unauthenticated FastAPI `/docs` endpoint exposes full API schema | 🟠 High | Disable OpenAPI UI endpoints in production builds |
| R-01 | No audit log for operator actions | 🟠 High | Append-only audit log with timestamp, user, action, and target fields |
| D-01 | Unbounded subprocess spawning allows resource exhaustion | 🟠 High | Job concurrency cap, API rate limiter, worker pool |
| E-01 | Backend likely runs as root enabling container escape post-exploitation | 🟠 High | Non-root user, dropped capabilities, seccomp profile in Dockerfile |
| E-02 | SSRF to RFC 1918 / cloud metadata via tool runner scope | 🟠 High | Block internal IP ranges in scope validator; egress network policy |
| S-03 | HTTPS-only session flag can be disabled via environment override | 🟡 Medium | Remove override capability; test in CI |
| T-04 | Malicious tool output injection via crafted target responses | 🟡 Medium | Treat subprocess stdout as untrusted; sanitise before rendering |
| I-03 | Verbose stack traces returned in API error responses | 🟡 Medium | Generic error handler in production; log detail server-side only |
| E-03 | Unpinned supply-chain dependencies | 🟡 Medium | Pin all deps; run `pip-audit` / `npm audit` in CI |
| T-02 | Path traversal in workpapers file download | 🟡 Medium | Canonicalise paths; assert within data directory |
| T-03 | SQLite DB writable via broad Docker volume permissions | 🟢 Low | Restrict volume permissions; consider migration to PostgreSQL |
| R-02 | No integrity metadata for scan output files | 🟢 Low | SHA-256 digests at write time; verify before packaging |
| D-02 | Unbounded file upload size risks volume exhaustion | 🟢 Low | Upload size limit in FastAPI; Docker volume quota |
| I-04 | Flat auth model allows cross-project data access | 🟢 Low | Project-scoped access control on all file and job endpoints |

---

## 6. Recommendations

### 6.1 Immediate — Before Any Production Deployment

- Remove the demo engagement data from the repository and purge git history (`git filter-repo` or BFG Repo Cleaner). Add `backend/data/` to `.gitignore`.
- Replace the default `forsight`/`forsight` credentials and the `change-me-in-production` secret key. Add a startup-time assertion that fails if either placeholder value is detected.
- Disable FastAPI's auto-generated `/docs` and `/redoc` routes (set `openapi_url=None` or guard with authentication middleware).
- Implement strict allowlist validation on all target input fields — accept only valid IPv4, IPv6, and RFC 1123 hostnames; reject RFC 1918, link-local, and loopback ranges.
- Refactor all subprocess calls to use the list form (`subprocess.run(['nmap', '-p', ports, target], ...)`) with `shell=False`; never interpolate user input into a shell string.

### 6.2 Short-Term — Next Release

- Add an append-only audit log recording every authenticated action: timestamp, session user, HTTP method, endpoint, and derived target scope.
- Implement a job concurrency limit and API rate limiter ([slowapi](https://github.com/laurentS/slowapi) is idiomatic for FastAPI) to prevent resource exhaustion from bulk tool submissions.
- Configure the backend Docker container to run as a non-root user, drop all Linux capabilities except those strictly required, and apply a restrictive seccomp profile. Never mount the Docker socket.
- Implement generic error responses in production (`debug=False`); log full stack traces to a server-side log file only.
- Add project-scoped access control: verify that the authenticated session user has membership of the requested project before serving any file, job, or host endpoint.

### 6.3 Medium-Term — Backlog

- Pin all Python and Node.js dependencies to exact versions and add `pip-audit` / `npm audit` to a CI pipeline (GitHub Actions). Enforce build failure on any known high/critical CVE.
- Compute and store a SHA-256 digest for each scan output file immediately after write. Verify the digest before including the file in a workpapers zip.
- Enforce path traversal protection on all file-serving endpoints: `os.path.realpath()` the resolved path and assert it falls within `FORSIGHT_DATA_DIR` before opening.
- Evaluate migration from SQLite to PostgreSQL for future multi-user or team deployment scenarios; enforce strict file permissions on the SQLite volume in the interim.
- Implement `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` response headers in the nginx configuration.

---

## 7. Appendix — STRIDE Reference

| Category | Property Violated | Description |
|---|---|---|
| S — Spoofing | Authentication | Impersonating a user or system component |
| T — Tampering | Integrity | Unauthorised modification of data or code |
| R — Repudiation | Non-repudiation | Denying performance of an action without audit capability |
| I — Information Disclosure | Confidentiality | Exposing information to unauthorised parties |
| D — Denial of Service | Availability | Denying legitimate users access to resources |
| E — Elevation of Privilege | Authorisation | Gaining capabilities beyond those intended |

STRIDE is a threat modelling framework originally developed by Microsoft. Each category maps to a security property and a set of mitigations. When combined with a structured threat register and data flow diagram analysis, it provides a systematic basis for identifying and prioritising security controls before, during, and after development.
