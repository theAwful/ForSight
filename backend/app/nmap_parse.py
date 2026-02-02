"""Shared nmap output parsing. All post-nmap phases use this to get targets by port."""

import re
from pathlib import Path


def get_ports_by_host(results_dir: Path) -> dict[str, list[int]]:
    """Parse nmap_ports.txt / nmap_services.txt; return host -> sorted list of open TCP ports."""
    by_host: dict[str, list[int]] = {}
    current_host = None
    for fname in ("nmap_ports.txt", "nmap_services.txt"):
        path = results_dir / fname
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if "Nmap scan report for" in line:
                m = re.search(r"for (\S+)", line)
                if m:
                    current_host = m.group(1).strip("()")
            m = re.search(r"(\d+)/tcp\s+open", line)
            if m and current_host:
                port = int(m.group(1))
                by_host.setdefault(current_host, [])
                if port not in by_host[current_host]:
                    by_host[current_host].append(port)
                by_host[current_host].sort()
    return by_host


def nmap_output_exists(results_dir: Path) -> bool:
    """True if any nmap result file exists (so downstream phases can use nmap data)."""
    for fname in ("nmap_ports.txt", "nmap_services.txt"):
        if (results_dir / fname).exists():
            return True
    return False


def get_hosts_for_ports(results_dir: Path, ports: list[int]) -> list[str]:
    """
    Return list of "host:port" for every (host, port) where port is in the given set.
    Used by web (web ports), SSL (ssl ports), legacy (ftp/smb/etc) phases.
    """
    port_set = set(ports)
    by_host = get_ports_by_host(results_dir)
    out: list[str] = []
    for host, open_ports in by_host.items():
        for p in open_ports:
            if p in port_set:
                out.append(f"{host}:{p}")
    return out


def get_ports_with_versions(results_dir: Path) -> dict[str, list[dict]]:
    """
    Parse nmap -sV output for port + service/version. Returns host -> list of
    {port, service?, product?, version?} for the Hosts tab.
    """
    # nmap_services.txt has -sV output; nmap_ports.txt has only port/open
    by_host: dict[str, list[dict]] = {}
    current_host = None
    path = results_dir / "nmap_services.txt"
    if not path.exists():
        # Fallback: ports only (no version) from either file
        for host, ports in get_ports_by_host(results_dir).items():
            by_host[host] = [{"port": p, "service": None, "product": None, "version": None} for p in ports]
        return by_host
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if "Nmap scan report for" in line:
            m = re.search(r"for (\S+)", line)
            if m:
                current_host = m.group(1).strip("()")
        # 80/tcp   open  http    Apache httpd 2.4.41
        m = re.match(r"(\d+)/tcp\s+open\s+(\S*)\s*(.*)", line)
        if m and current_host:
            port = int(m.group(1))
            service = m.group(2).strip() or None
            rest = m.group(3).strip()
            product, version = None, None
            if rest:
                # "Apache httpd 2.4.41" -> product "Apache httpd", version "2.4.41"
                ver_match = re.search(r"\s+([\d.+\-~]+)\s*$", rest)
                if ver_match:
                    version = ver_match.group(1).strip()
                    product = rest[: ver_match.start()].strip() or rest
                else:
                    product = rest
            by_host.setdefault(current_host, [])
            by_host[current_host].append({
                "port": port,
                "service": service,
                "product": product,
                "version": version,
            })
    for host in by_host:
        by_host[host].sort(key=lambda x: x["port"])
    return by_host
