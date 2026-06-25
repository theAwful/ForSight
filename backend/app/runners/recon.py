"""Recon runners: one runner per tool (subfinder, dnsrecon, amass, theHarvester, whois, cloud, leaked)."""

from pathlib import Path
from typing import List, Optional

from app.config import settings
from app.runners.base import run_tool, run_tool_stream
from .dehashed import run_recon_dehashed

async def _write_header(stream_path: Optional[Path], tool_name: str) -> None:
    if stream_path:
        stream_path.parent.mkdir(parents=True, exist_ok=True)
        with open(stream_path, "a") as f:
            f.write(f"=== {tool_name} ===\n")


async def run_recon_subfinder(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    out = results_dir / "recon_subfinder.txt"
    if not domains:
        if stream_path:
            stream_path.write_text("# No domains in ROE.\n")
        out.write_text("# No domains in ROE.\n")
        return 0, "", "", stream_path or out
    await _write_header(stream_path, "subfinder")
    args = [settings.subfinder_path, "-o", str(out)]
    for d in domains:
        args.extend(["-d", d])
    code = await run_tool_stream(args, stream_path or out, job_id=job_id, append=True, timeout=600)
    return code, "", "", stream_path or out


async def run_recon_dnsrecon(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    if not domains:
        if stream_path:
            stream_path.write_text("# No domains in ROE.\n")
        return 0, "", "", stream_path
    out = results_dir / "recon_dnsrecon.txt"
    lines = []
    for d in domains[:10]:
        await _write_header(stream_path, f"dnsrecon -d {d}")
        args = [settings.dnsrecon_path, "-d", d, "-t", "std", "-t", "axfr", "-t", "brt"]
        code = await run_tool_stream(args, stream_path or out, job_id=job_id, append=True, timeout=300)
        lines.append(f"--- {d} --- (code {code})")
    if out and not stream_path:
        out.write_text("\n".join(lines))
    return 0, "", "", stream_path or out


async def run_recon_amass(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    if not domains:
        if stream_path:
            stream_path.write_text("# No domains in ROE.\n")
        return 0, "", "", stream_path
    out = results_dir / "recon_amass.txt"
    await _write_header(stream_path, "amass")
    args = [settings.amass_path, "enum", "-passive", "-o", str(out)]
    for d in domains[:5]:
        args.extend(["-d", d])
    code = await run_tool_stream(args, stream_path or out, job_id=job_id, append=True, timeout=900)
    return code, "", "", stream_path or out


async def run_recon_theharvester(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    if not domains:
        if stream_path:
            stream_path.write_text("# No domains in ROE.\n")
        return 0, "", "", stream_path
    out = results_dir / "recon_theharvester.txt"
    for d in domains[:5]:
        await _write_header(stream_path, f"theHarvester -d {d}")
        args = [settings.theharvester_path, "-d", d, "-b", "all"]
        code = await run_tool_stream(args, stream_path or out, job_id=job_id, append=True, timeout=600)
    return 0, "", "", stream_path or out


async def run_recon_whois(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    if not domains:
        if stream_path:
            stream_path.write_text("# No domains in ROE.\n")
        return 0, "", "", stream_path
    out = results_dir / "recon_whois.txt"
    for d in domains[:20]:
        await _write_header(stream_path, f"whois {d}")
        args = [settings.whois_path, d]
        await run_tool_stream(args, stream_path or out, job_id=job_id, append=True, timeout=30)
    return 0, "", "", stream_path or out


async def run_recon_cloud(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    output_path = results_dir / "recon_cloud.txt"
    if not domains:
        if stream_path:
            stream_path.write_text("# No domains in ROE for CloudEnum.\n")
        output_path.write_text("# No domains in ROE.\n")
        return 0, "", "", stream_path or output_path
    # cloud_enum -k domain.com (one -k per domain)
    args = [settings.cloudenum_path]
    for d in domains[:20]:
        args.extend(["-k", d])
    await _write_header(stream_path, "CloudEnum")
    code = await run_tool_stream(args, stream_path or output_path, job_id=job_id, append=True, timeout=900)
    return code, "", "", stream_path or output_path


async def run_recon_leaked(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    return await run_recon_dehashed(
        project_id=project_id,
        ips=ips,
        domains=domains,
        results_dir=results_dir,
        stream_path=stream_path,
        job_id=job_id,
        **kwargs,
    )
