"""Aggregate scan results by host for the Hosts/Summaries view."""

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from app.nmap_parse import get_ports_by_host, get_ports_with_versions


def _normalize_url_for_match(url: str) -> str:
    """Normalize URL for matching (lowercase host, default port)."""
    if not url or not url.startswith(("http://", "https://")):
        return (url or "").strip().lower()
    parsed = urlparse(url)
    host = (parsed.hostname or parsed.netloc or "").lower()
    port = parsed.port
    scheme = parsed.scheme or "http"
    if not host:
        return url.strip().lower()
    if port and port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _parse_gowitness_targets_from_job_outputs(results_dir: Path) -> dict[str, str]:
    """
    Parse all job_*.txt in results_dir for gowitness-style lines:
    INFO result target=URL ... have-screenshot=true
    Return dict: normalized_url -> host (so we can assign screenshots to hosts).
    """
    url_to_host: dict[str, str] = {}
    for path in results_dir.glob("job_*.txt"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                if "target=" not in line or "have-screenshot=true" not in line:
                    continue
                m = re.search(r"target=(https?://[^\s]+)", line)
                if m:
                    url = m.group(1).strip()
                    norm = _normalize_url_for_match(url)
                    host = _extract_host_from_url(url)
                    if host:
                        url_to_host[norm] = host
        except Exception:
            continue
    return url_to_host


def _url_from_gowitness_filename(filename: str) -> str | None:
    """
    Derive possible URL from gowitness-style filename for matching to job output.
    Handles:
    - scheme---host-port.ext (e.g. http---intragin.awfulsecurity.org-80.jpeg)
    - example.com_80.png, https_example.com_443.png, http_intragin_awfulsecurity_org_80.png
    """
    if not filename:
        return None
    p = Path(filename)
    if p.suffix.lower() not in (".png", ".jpg", ".jpeg"):
        return None
    stem = p.stem
    # New gowitness format: http---host-port or https---host-port (host can contain dots)
    m = re.match(r"^(https?)---(.+)-(\d+)$", stem)
    if m:
        scheme, host, port_str = m.group(1), m.group(2), m.group(3)
        port = int(port_str)
        if port in (80, 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"
    if "_" not in stem:
        return None
    if stem.startswith("http"):
        parts = stem.split("_", 1)
        scheme = (parts[0] + "://") if parts[0] in ("http", "https") else "http://"
        rest = parts[1] if len(parts) > 1 else ""
    else:
        scheme = "http://"
        rest = stem
    if not rest:
        return None
    parts = rest.rsplit("_", 1)
    host_part = parts[0].replace("_", ".")  # intragin_awfulsecurity_org -> intragin.awfulsecurity.org
    try:
        port_part = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else (443 if "https" in scheme else 80)
    except (ValueError, IndexError):
        port_part = 80
    if port_part in (80, 443):
        url = f"{scheme}{host_part}"
    else:
        url = f"{scheme}{host_part}:{port_part}"
    return url


def _extract_host_from_url(url: str) -> str:
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        return url.split(":")[0] if ":" in url else url
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port
    if port and port not in (80, 443):
        return f"{host}:{port}"
    return host or ""


def canonical_host(host_or_url: str) -> str:
    """Single key per host: hostname or IP only, no port. Dedupe e.g. example.com and example.com:443."""
    s = (host_or_url or "").strip()
    if not s:
        return ""
    if s.startswith(("http://", "https://")):
        parsed = urlparse(s)
        return (parsed.hostname or parsed.netloc or "").lower()
    # host:port or host
    if ":" in s:
        return s.split(":", 1)[0].strip().lower()
    return s.lower()


def _port_from_url(url: str) -> int | None:
    """Extract port from URL; 80/443 if default. None if not parseable."""
    if not url or not url.startswith(("http://", "https://")):
        if ":" in (url or ""):
            try:
                return int((url or "").split(":", 1)[1].strip())
            except (ValueError, IndexError):
                pass
        return None
    parsed = urlparse(url)
    return parsed.port if parsed.port is not None else (443 if (parsed.scheme or "").lower() == "https" else 80)


def _port_from_screenshot(s: dict) -> int | None:
    """Port from screenshot URL or filename (e.g. http---host-8080.jpeg -> 8080)."""
    url = s.get("url") or ""
    if url:
        p = _port_from_url(url if url.startswith("http") else f"http://{url}")
        if p is not None:
            return p
    fn = s.get("filename") or ""
    if not fn:
        return None
    stem = Path(fn).stem
    m = re.match(r"^(?:https?)---.+?-(\d+)$", stem)
    if m:
        return int(m.group(1))
    if "_" in stem:
        parts = stem.rsplit("_", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return int(parts[1])
    return None


def _load_nessus_findings_by_host(results_dir: Path) -> dict[str, list[dict]]:
    """Load Nessus imports and return canonical_host -> list of vuln dicts (with scan_id, scan_name)."""
    path = results_dir / "nessus_imports.json"
    out: dict[str, list[dict]] = {}
    if not path.exists():
        return out
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        scans = data.get("scans") or {}
        for sid, scan in scans.items():
            scan_id = scan.get("scan_id") or sid
            scan_name = scan.get("scan_name") or ""
            for h in scan.get("hosts") or []:
                host_ip = (h.get("host_ip") or h.get("name") or "").strip()
                c = canonical_host(host_ip)
                if not c:
                    continue
                for v in h.get("vulns") or []:
                    out.setdefault(c, []).append({
                        **v,
                        "scan_id": scan_id,
                        "scan_name": scan_name,
                        "source": "nessus",
                    })
    except Exception:
        pass
    return out


def _parse_nuclei_findings(results_dir: Path) -> list[dict]:
    """Parse web_nuclei.json for findings (host, template, etc.)."""
    path = results_dir / "web_nuclei.json"
    if not path.exists():
        return []
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
        findings = []
        # May be one JSON array on one line or one JSON object per line
        stripped = data.strip()
        if stripped.startswith("["):
            obj = json.loads(data)
            findings = [x for x in (obj if isinstance(obj, list) else []) if isinstance(x, dict)]
        else:
            for line in data.splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        findings.append(obj)
                    elif isinstance(obj, list):
                        findings.extend(x for x in obj if isinstance(x, dict))
                except json.JSONDecodeError:
                    continue
        return findings
    except Exception:
        return []


def _parse_ssl_summaries(results_dir: Path) -> dict[str, list[str]]:
    """Parse ssl_enum.txt for host:port sections; return canonical_host -> list of one-line summaries."""
    path = results_dir / "ssl_enum.txt"
    out: dict[str, list[str]] = {}
    if not path.exists():
        return out
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        current_host = None
        lines_for_host: list[str] = []
        for line in text.splitlines():
            if "===" in line and "===" in line[line.index("===") + 3 :]:
                if current_host and lines_for_host:
                    summary = " ".join(" ".join(lines_for_host).split())[:200]
                    if summary:
                        out.setdefault(canonical_host(current_host), []).append(f"SSL: {summary}")
                m = re.search(r"=== (\S+:\d+) ===", line) or re.search(r"=== (\S+) ===", line)
                current_host = m.group(1).strip() if m else None
                lines_for_host = []
            elif current_host:
                lines_for_host.append(line.strip())
        if current_host and lines_for_host:
            summary = " ".join(" ".join(lines_for_host).split())[:200]
            if summary:
                out.setdefault(canonical_host(current_host), []).append(f"SSL: {summary}")
    except Exception:
        pass
    return out


def _parse_legacy_summaries(results_dir: Path) -> dict[str, list[str]]:
    """Parse legacy_*.txt for host mentions; return canonical_host -> list of protocol hints (e.g. 'SNMP: public')."""
    out: dict[str, list[str]] = {}
    for name, pattern, label in [
        ("legacy_snmp.txt", re.compile(r"--- (\S+):?\d* .*community=(\w+)", re.I), "SNMP"),
        ("legacy_ftp.txt", re.compile(r"--- (\S+):?\d* ---", re.I), "FTP"),
        ("legacy_smb.txt", re.compile(r"--- (\S+) ---", re.I), "SMB"),
        ("legacy_banners.txt", re.compile(r"(\S+):(\d+) -> (.+)", re.I), "Banner"),
        ("legacy_ldap.txt", re.compile(r"--- (\S+):?\d* ---", re.I), "LDAP"),
    ]:
        path = results_dir / name
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                if name == "legacy_banners.txt":
                    m = pattern.search(line)
                    if m:
                        host, port, banner = m.group(1), m.group(2), (m.group(3) or "")[:60]
                        c = canonical_host(host)
                        out.setdefault(c, []).append(f"{label} {port}: {banner}")
                else:
                    m = pattern.search(line)
                    if m:
                        host = m.group(1).strip()
                        c = canonical_host(host)
                        if name == "legacy_snmp.txt":
                            out.setdefault(c, []).append(f"{label}: {m.group(2)}")
                        else:
                            out.setdefault(c, []).append(label)
        except Exception:
            continue
    return out


def _host_from_gowitness_filename(filename: str) -> str:
    """Derive host from gowitness-style filename. Supports scheme---host-port.ext and host_port.png."""
    if not filename:
        return ""
    p = Path(filename)
    if p.suffix.lower() not in (".png", ".jpg", ".jpeg"):
        return ""
    stem = p.stem
    # New format: http---intragin.awfulsecurity.org-80 -> intragin.awfulsecurity.org
    m = re.match(r"^https?---(.+)-(\d+)$", stem)
    if m:
        return m.group(1).strip()
    # Old format: example.com_80 or https_example.com_443
    if stem.startswith("http"):
        parts = stem.split("_", 1)
        stem = parts[1] if len(parts) > 1 else ""
    if "_" in stem:
        stem = stem.rsplit("_", 1)[0].replace("_", ".")
    return stem.strip()


def _screenshots_with_host(
    manifest: list[dict],
    url_to_host: dict[str, str],
    screenshots_dir: Path,
) -> list[dict]:
    """
    Add 'host' to each screenshot: prefer match from gowitness job output (target=URL),
    else URL from manifest, else host from filename.
    """
    seen_filenames: set[str] = set()
    out = []
    for s in manifest:
        fn = s.get("filename") or ""
        seen_filenames.add(fn)
        url = s.get("url") or ""
        host = None
        derived_url = _url_from_gowitness_filename(fn)
        if derived_url:
            norm = _normalize_url_for_match(derived_url)
            host = url_to_host.get(norm)
        if not host and url:
            host = _extract_host_from_url(url)
        if not host:
            host = _host_from_gowitness_filename(fn)
        out.append({**s, "url": url or derived_url or "", "host": host or ""})
    # Include any screenshot file in folder not in manifest (dynamic discovery)
    for path in screenshots_dir.glob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".png", ".jpg", ".jpeg"):
            continue
        fn = path.name
        if fn in seen_filenames:
            continue
        seen_filenames.add(fn)
        derived_url = _url_from_gowitness_filename(fn)
        norm = _normalize_url_for_match(derived_url or "")
        host = url_to_host.get(norm) if norm else None
        if not host and derived_url:
            host = _extract_host_from_url(derived_url)
        if not host:
            host = _host_from_gowitness_filename(fn)
        out.append({"filename": fn, "url": derived_url or "", "host": host or ""})
    return out


def aggregate_hosts(project_id: int, results_dir: Path) -> list[dict]:
    """Build list of hosts (one per canonical host) with ports, by_port (screenshots/findings per port), screenshots, findings."""
    if not results_dir.exists():
        return []
    ports_by_host_raw = get_ports_by_host(results_dir)
    ports_with_versions_raw = get_ports_with_versions(results_dir)
    nuclei_findings = _parse_nuclei_findings(results_dir)
    nessus_findings_by_host = _load_nessus_findings_by_host(results_dir)
    screenshots_dir = results_dir / "screenshots"
    url_to_host = _parse_gowitness_targets_from_job_outputs(results_dir)
    manifest_path = screenshots_dir / "manifest.json"
    manifest_data: list[dict] = []
    if manifest_path.exists():
        try:
            data = json.loads(manifest_path.read_text())
            manifest_data = data if isinstance(data, list) else []
        except Exception:
            pass
    screenshots = _screenshots_with_host(manifest_data, url_to_host, screenshots_dir)

    # Merge ports by canonical host (so example.com and example.com:443 become one host)
    ports_by_host: dict[str, list[int]] = {}
    ports_with_versions: dict[str, list[dict]] = {}
    for raw_host, ports in ports_by_host_raw.items():
        c = canonical_host(raw_host)
        ports_by_host.setdefault(c, []).extend(ports)
    for raw_host, detail in ports_with_versions_raw.items():
        c = canonical_host(raw_host)
        ports_with_versions.setdefault(c, []).extend(detail)
    for c in ports_by_host:
        ports_by_host[c] = sorted(set(ports_by_host[c]))
    for c in ports_with_versions:
        seen_ports: set[int] = set()
        uniq: list[dict] = []
        for p in ports_with_versions[c]:
            port = (p.get("port") if isinstance(p.get("port"), int) else None) or (int(p["port"]) if p.get("port") else None)
            if port is not None and port not in seen_ports:
                seen_ports.add(port)
                uniq.append(p)
        ports_with_versions[c] = uniq

    ssl_summaries = _parse_ssl_summaries(results_dir)
    legacy_summaries = _parse_legacy_summaries(results_dir)

    # Build set of canonical hosts from ports, findings, screenshots, ssl, legacy
    hosts_set: set[str] = set()
    hosts_set.update(ports_by_host.keys())
    hosts_set.update(ssl_summaries.keys())
    hosts_set.update(legacy_summaries.keys())
    for f in nuclei_findings:
        if not isinstance(f, dict):
            continue
        host = _extract_host_from_url((f.get("host") or f.get("matched-at") or "").strip())
        if host:
            hosts_set.add(canonical_host(host))
    for s in screenshots:
        h = (s.get("host") or _extract_host_from_url(s.get("url") or "")).strip()
        if h:
            hosts_set.add(canonical_host(h))
    hosts_set.update(nessus_findings_by_host.keys())

    result = []
    for host in sorted(hosts_set):
        host_screenshots = [
            x for x in screenshots
            if canonical_host(x.get("host") or _extract_host_from_url(x.get("url") or "") or _host_from_gowitness_filename(x.get("filename") or "")) == host
        ]
        # Collect all findings for this host, then dedupe by template-id (one per template)
        raw_findings: list[dict] = []
        for f in nuclei_findings:
            if not isinstance(f, dict):
                continue
            h = _extract_host_from_url((f.get("host") or f.get("matched-at") or "").strip())
            if canonical_host(h) == host:
                raw_findings.append({
                    "template": f.get("template-id"),
                    "info": f.get("info", {}),
                    "matched_at": (f.get("matched-at") or f.get("host") or "").strip(),
                })
        seen_templates: set[str] = set()
        host_findings: list[dict] = []
        for f in raw_findings:
            tid = (f.get("template") or "").strip()
            if not tid or tid in seen_templates:
                continue
            seen_templates.add(tid)
            host_findings.append(f)

        # Group by port; findings per port also deduped by template
        by_port: dict[str, dict] = {}
        for p in ports_by_host.get(host, []):
            by_port[str(p)] = {"screenshots": [], "findings": []}
        for s in host_screenshots:
            port = _port_from_screenshot(s)
            key = str(port) if port is not None else "0"
            if key not in by_port:
                by_port[key] = {"screenshots": [], "findings": []}
            by_port[key]["screenshots"].append(s)
        port_seen: dict[str, set[str]] = {}
        for f in host_findings:
            port = _port_from_url(f.get("matched_at") or "")
            port_key = str(port) if port is not None else "0"
            if port_key not in by_port:
                by_port[port_key] = {"screenshots": [], "findings": []}
            if port_key not in port_seen:
                port_seen[port_key] = set()
            tid = (f.get("template") or "").strip()
            if tid and tid not in port_seen[port_key]:
                port_seen[port_key].add(tid)
                by_port[port_key]["findings"].append(f)

        seen_insight: set[str] = set()
        insights: list[str] = []
        for line in (ssl_summaries.get(host, [])[:3] + legacy_summaries.get(host, [])[:5]):
            if line and line not in seen_insight:
                seen_insight.add(line)
                insights.append(line)

        result.append({
            "host": host,
            "ports": ports_by_host.get(host, []),
            "ports_detail": ports_with_versions.get(host, []),
            "by_port": by_port,
            "screenshots": host_screenshots,
            "findings": host_findings,
            "nessus_findings": nessus_findings_by_host.get(host, []),
            "insights": insights,
        })
    return result
