"""DeHashed runner — wraps dehashapitool CLI, matching ForSight's runner pattern."""

import shutil
from pathlib import Path
from typing import List, Optional

from app.config import settings
from app.runners.base import run_tool_stream


async def run_recon_dehashed(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    output_path = results_dir / "recon_dehashed.csv"

    if not domains:
        msg = "# No domains in ROE for DeHashed.\n"
        if stream_path:
            stream_path.write_text(msg)
        output_path.write_text(msg)
        return 0, "", "", stream_path or output_path

    api_key = (settings.dehashed_key or "").strip()
    if not api_key:
        msg = "# DeHashed skipped — FORSIGHT_DEHASHED_KEY not set in config.\n"
        if stream_path:
            stream_path.write_text(msg)
        output_path.write_text(msg)
        return 0, "", "", stream_path or output_path

    tool = shutil.which("dehashapitool") or shutil.which("dat")
    if not tool:
        msg = "# dehashapitool not found on PATH. Install: pipx install git+https://github.com/hmaverickadams/DeHashed-API-Tool\n"
        if stream_path:
            stream_path.write_text(msg)
        output_path.write_text(msg)
        return 1, "", msg, stream_path or output_path

    # Run once per domain (same pattern as dnsrecon/whois)
    last_code = 0
    for d in domains[:10]:
        if stream_path:
            with open(stream_path, "a") as f:
                f.write(f"=== dehashed -d {d} ===\n")
        args = [tool, "-d", d, "-o", str(output_path), "--key", api_key]
        last_code = await run_tool_stream(
            args, stream_path or output_path, job_id=job_id, append=True, timeout=120
        )

    return last_code, "", "", stream_path or output_path
