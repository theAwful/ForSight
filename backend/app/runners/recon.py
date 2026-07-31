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


async def _append_stream(stream_path: Optional[Path], text: str) -> None:
    if not stream_path:
        return
    stream_path.parent.mkdir(parents=True, exist_ok=True)
    with open(stream_path, "a", encoding="utf-8") as f:
        f.write(text)


async def _run_and_dual_write(
    args: List[str],
    tool_label: str,
    out: Path,
    stream_path: Optional[Path],
    timeout: int,
) -> None:
    """Run once; append stdout/stderr to both the named artifact and the job stream."""
    header = f"=== {tool_label} ===\n"
    _code, stdout, stderr = await run_tool(tool_label, args, timeout=timeout)
    body = (stdout or "") + (("\n" + stderr) if stderr else "")
    if body and not body.endswith("\n"):
        body += "\n"
    body += "\n"
    block = header + body
    with open(out, "a", encoding="utf-8") as f:
        f.write(block)
    await _append_stream(stream_path, block)


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
    out = results_dir / "recon_dnsrecon.txt"
    if not domains:
        msg = "# No domains in ROE.\n"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out
    out.write_text("", encoding="utf-8")
    for d in domains[:10]:
        args = [settings.dnsrecon_path, "-d", d, "-t", "std", "-t", "axfr", "-t", "brt"]
        await _run_and_dual_write(args, f"dnsrecon -d {d}", out, stream_path, timeout=300)
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
    out = results_dir / "recon_theharvester.txt"
    if not domains:
        msg = "# No domains in ROE.\n"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out
    out.write_text("", encoding="utf-8")
    for d in domains[:5]:
        args = [settings.theharvester_path, "-d", d, "-b", "all"]
        await _run_and_dual_write(args, f"theHarvester -d {d}", out, stream_path, timeout=600)
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
    out = results_dir / "recon_whois.txt"
    if not domains:
        msg = "# No domains in ROE.\n"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out
    out.write_text("", encoding="utf-8")
    for d in domains[:20]:
        args = [settings.whois_path, d]
        await _run_and_dual_write(args, f"whois {d}", out, stream_path, timeout=30)
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
    args = [settings.cloudenum_path]
    for d in domains[:20]:
        args.extend(["-k", d])
    await _write_header(stream_path, "CloudEnum")
    # Dual-write: capture once into named artifact and mirror to job stream
    _code, stdout, stderr = await run_tool("CloudEnum", args, output_path=output_path, timeout=900)
    body = (stdout or "") + (("\n" + stderr) if stderr else "")
    if stream_path:
        await _append_stream(stream_path, body if body.endswith("\n") else body + "\n")
    return _code, "", "", stream_path or output_path


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
