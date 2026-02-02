"""Email security: SPF/DKIM/DMARC (Domain Security Scanner)."""

from pathlib import Path
from typing import List, Optional

from app.runners.base import run_tool


async def run_email_security(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    output_path = results_dir / "email_security.txt"
    if not domains:
        msg = "# No domains in ROE for email security scan.\n"
        output_path.write_text(msg)
        if stream_path:
            stream_path.write_text(msg)
        return 0, "", "", stream_path or output_path
    text = (
        "# Email security (SPF/DKIM/DMARC)\n"
        "# Run Domain Security Scanner manually or integrate tool.\n"
        f"# Domains: {domains}\n"
    )
    output_path.write_text(text)
    if stream_path:
        stream_path.write_text(text)
    return 0, text, "", stream_path or output_path
