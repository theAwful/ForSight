"""Nmap runners: TCP top 5000 ports (for downstream tooling), service fingerprinting."""

from pathlib import Path
from typing import List, Optional

from app.config import settings
from app.runners.base import run_tool, run_tool_stream


async def run_nmap_ports(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    # Nmap accepts both IPs and hostnames; include domains from ROE
    targets = (ips + domains)[:30]
    if not targets:
        out = results_dir / "nmap_ports.txt"
        msg = "# No IPs or domains in ROE; add targets to run nmap.\n"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out
    output_path = results_dir / "nmap_ports.txt"
    # Top 5000 TCP ports so results feed into subsequent tooling (web URLs, etc.)
    args = [
        settings.nmap_path,
        "-sS", "--top-ports", "5000", "-T4",
        "-oN", str(output_path), "--open",
        *targets,
    ]
    if stream_path is not None:
        code = await run_tool_stream(args, stream_path, job_id=job_id, append=True, timeout=3600)
        return code, "", "", stream_path
    from app.runners.base import run_tool as run_tool_blocking
    code, stdout, stderr = await run_tool_blocking("nmap_ports", args, output_path=output_path, timeout=3600)
    return code, stdout, stderr, output_path


async def run_nmap_services(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    alive_ips: Optional[List[str]] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    # Include domains so nmap -sV runs on hostnames from ROE too
    use_ips = alive_ips or ips
    targets = (use_ips + domains)[:30]
    if not targets:
        out = results_dir / "nmap_services.txt"
        msg = "# No IPs or domains available for service scan.\n"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out
    output_path = results_dir / "nmap_services.txt"
    args = [
        settings.nmap_path,
        "-sV", "-T4", "-oN", str(output_path),
        *targets,
    ]
    if stream_path is not None:
        code = await run_tool_stream(args, stream_path, job_id=job_id, append=True, timeout=3600)
        return code, "", "", stream_path
    from app.runners.base import run_tool as run_tool_blocking
    code, stdout, stderr = await run_tool_blocking("nmap_services", args, output_path=output_path, timeout=3600)
    return code, stdout, stderr, output_path
