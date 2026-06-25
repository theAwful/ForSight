import asyncio
import shutil
from pathlib import Path


async def run_dehashed(domain: str, output_dir: Path, api_key: str, yield_line):
    """
    Wrapper for dehashapitool (hmaverickadams/DeHashed-API-Tool).
    Streams output line-by-line via yield_line callback, matching ForSight's runner pattern.
    """
    tool = shutil.which("dehashapitool") or shutil.which("dat")
    if not tool:
        yield_line("[dehashed] ERROR: dehashapitool not found on PATH. "
                   "Install with: pipx install git+https://github.com/hmaverickadams/DeHashed-API-Tool")
        return

    output_file = output_dir / "dehashed_results.csv"
    cmd = [
        tool,
        "-d", domain,
        "-o", str(output_file),
        "--key", api_key,
    ]

    yield_line(f"[dehashed] Running: {' '.join(cmd[:4])} --key <redacted> -o {output_file}")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    async for raw in proc.stdout:
        line = raw.decode(errors="replace").rstrip()
        if line:
            yield_line(f"[dehashed] {line}")

    await proc.wait()
    if output_file.exists():
        yield_line(f"[dehashed] Results saved to {output_file}")
    yield_line(f"[dehashed] Done (exit code {proc.returncode})")
