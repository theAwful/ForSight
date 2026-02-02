"""Password spraying on external appliance login portals (medusa, etc.)."""

from pathlib import Path
from typing import List, Optional

from app.runners.base import run_tool


async def run_password_spray(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """Password spraying (weak/default creds). Use with caution; no DoS."""
    output_path = results_dir / "password_spray.txt"
    text = (
        "# Password spraying (Burp, medusa)\n"
        "# Run manually per ROE to avoid lockouts/DoS.\n"
        f"# Targets: {ips[:20]} {domains[:20]}\n"
    )
    output_path.write_text(text)
    if stream_path:
        stream_path.write_text(text)
    return 0, text, "", stream_path or output_path
