"""Web URL discovery: prefer nmap results (web ports), fallback to masscan. ROE domains always included."""

import re
from pathlib import Path
from typing import List, Optional

from app.config import settings
from app.nmap_parse import get_hosts_for_ports, nmap_output_exists
from app.runners.base import run_tool

# Web ports: used when parsing nmap or when running masscan
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443, 4443, 10000]


def _urls_from_domains(domains: List[str], ips: List[str]) -> List[str]:
    """Build HTTP(S) URLs from domains and IPs (no port scan)."""
    urls = []
    for d in domains:
        if not d.startswith("http"):
            urls.append(f"https://{d}")
            urls.append(f"http://{d}")
    for ip in ips[:10]:
        urls.append(f"http://{ip}")
        urls.append(f"https://{ip}")
    return urls


def _hostport_to_url(host_port: str) -> str:
    """Convert 'host:port' to http(s) URL."""
    host, port = host_port.split(":", 1)
    port = int(port)
    scheme = "https" if port in (443, 8443, 9443, 4443) else "http"
    return f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"


async def get_web_urls(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    use_nmap: bool = False,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
) -> List[str]:
    """
    Return list of HTTP(S) URLs to scan. Workflow: use nmap results when available
    (web ports from nmap); otherwise run masscan for web ports. Always merges with
    domain-based URLs from ROE.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    domain_urls = _urls_from_domains(domains, ips)
    scan_urls: List[str] = []

    # Prefer nmap when available (nmap → web section targets web ports)
    if use_nmap or nmap_output_exists(results_dir):
        host_ports = get_hosts_for_ports(results_dir, WEB_PORTS)
        scan_urls = [_hostport_to_url(hp) for hp in host_ports]

    if not scan_urls and ips:
        # Run masscan for web ports
        masscan_out = results_dir / "web_masscan.txt"
        port_str = ",".join(str(p) for p in WEB_PORTS)
        args = [
            settings.masscan_path,
            "-p", port_str,
            "-oN", str(masscan_out),
            "--rate", "1000",
        ] + list(ips[:50])
        code, stdout, stderr = await run_tool(
            "masscan",
            args,
            output_path=masscan_out,
            timeout=600,
        )
        if masscan_out.exists():
            text = masscan_out.read_text(encoding="utf-8", errors="replace")
            # masscan output: "Discovered open port 80/tcp on 1.2.3.4"
            for m in re.finditer(r"port (\d+)/tcp on (\S+)", text):
                port, host = int(m.group(1)), m.group(2)
                scheme = "https" if port in (443, 8443, 9443, 4443) else "http"
                u = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
                scan_urls.append(u)

    combined = list(dict.fromkeys(domain_urls + scan_urls))
    return combined[:200]
