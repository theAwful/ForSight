"""SSL/TLS enumeration: testssl.sh, sslscan. Uses nmap results (SSL ports) when available."""

from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from app.config import settings
from app.nmap_parse import get_hosts_for_ports, nmap_output_exists
from app.runners.base import run_tool, run_tool_stream

# SSL/TLS-related ports: when nmap exists, target these from nmap output
SSL_PORTS = [443, 8443, 993, 995, 465, 636, 25, 587, 992, 994]


def _hosts_from_ips_domains(ips: List[str], domains: List[str]) -> List[str]:
    """Fallback: build host:port from ROE (domains:443, ips:443)."""
    hosts = []
    for d in domains:
        if "://" in d:
            parsed = urlparse(d)
            host = parsed.netloc or parsed.path
        else:
            host = d
        if ":" not in host:
            host = f"{host}:443"
        hosts.append(host)
    for ip in ips:
        hosts.append(f"{ip}:443")
    return hosts[:50]


async def run_ssl_enum(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    # Prefer nmap when available (enumeration phase fed by nmap)
    if nmap_output_exists(results_dir):
        hosts = get_hosts_for_ports(results_dir, SSL_PORTS)
    else:
        hosts = _hosts_from_ips_domains(ips, domains)
    if not hosts:
        out = results_dir / "ssl_enum.txt"
        msg = "# No IPs/domains in ROE for SSL check.\n"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out
    output_path = results_dir / "ssl_enum.txt"
    for h in hosts[:30]:
        parts = h.split(":", 1)
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443
        if stream_path:
            with open(stream_path, "a") as f:
                f.write(f"=== {host}:{port} ===\n")
        args = [settings.sslscan_path, host]
        if port != 443:
            args.extend(["--port", str(port)])
        if stream_path is not None:
            await run_tool_stream(args, stream_path, job_id=job_id, append=True, timeout=120)
        else:
            code, stdout, stderr = await run_tool("sslscan", args, output_path=None, timeout=120)
            output_path.write_text((output_path.read_text() if output_path.exists() else "") + f"\n=== {host} ===\n{stdout}\n{stderr}")
    return 0, "", "", stream_path or output_path
