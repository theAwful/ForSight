"""CMS enumeration: wpscan, droopescan (under web host section)."""

from pathlib import Path
from typing import List, Optional

from app.config import settings
from app.runners.base import run_tool, run_tool_stream
from app.runners.web_urls import get_web_urls


async def run_cms_enum(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    use_nmap: bool = False,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """Run CMS enum on web URLs (from masscan/nmap or domains)."""
    urls = await get_web_urls(project_id, ips, domains, results_dir, use_nmap=use_nmap)
    if not urls:
        targets = [f"https://{d}" if not d.startswith("http") else d for d in domains]
        if not targets:
            targets = [f"http://{ip}" for ip in ips[:5]]
    else:
        targets = urls[:10]
    output_path = results_dir / "cms_enum.txt"
    if not targets:
        msg = "# No URLs in ROE for CMS enum.\n"
        if stream_path:
            stream_path.write_text(msg)
        output_path.write_text(msg)
        return 0, "", "", stream_path or output_path
    combined = []
    for url in targets[:5]:
        if stream_path:
            with open(stream_path, "a") as f:
                f.write(f"=== {url} ===\n")
        args = [settings.wpscan_path, "--url", url, "--no-update"]
        if stream_path is not None:
            await run_tool_stream(args, stream_path, job_id=job_id, append=True, timeout=300)
        else:
            code, stdout, stderr = await run_tool("wpscan", args, output_path=None, timeout=300)
            combined.append(f"=== {url} ===\n{stdout}\n{stderr}")
    if not stream_path:
        output_path.write_text("\n".join(combined))
    return 0, "", "", stream_path or output_path
