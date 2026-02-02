"""Base runner: run a CLI tool, capture to file; streaming variant for live output and stop support."""

import asyncio
import os
from pathlib import Path
from typing import Dict, List, Optional

# Job ID -> asyncio.SubprocessProcess (for stop support). Accessed from runner thread and API.
RUNNING_JOBS: Dict[int, asyncio.subprocess.Process] = {}


async def run_tool(
    name: str,
    args: List[str],
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    output_path: Optional[Path] = None,
    timeout: int = 3600,
) -> tuple[int, str, str]:
    """
    Run a CLI tool. Returns (returncode, stdout, stderr).
    If output_path is set, also write combined output to file.
    """
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)
    proc = await asyncio.create_subprocess_exec(
        args[0],
        *args[1:],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=proc_env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        out = "Tool timed out.\n"
        if output_path:
            output_path.write_text(out)
        return -1, "", out
    out_bytes = stdout + b"\n" + stderr
    out_str = out_bytes.decode("utf-8", errors="replace")
    if output_path:
        output_path.write_text(out_str)
    return proc.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")


async def run_tool_stream(
    args: List[str],
    stream_path: Path,
    job_id: Optional[int] = None,
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    timeout: int = 3600,
    append: bool = True,
    suppress_stderr: bool = False,
) -> int:
    """
    Run a CLI tool with stdout (and optionally stderr) streamed to stream_path.
    When suppress_stderr=True, stderr is discarded (reduces noise from tools like gowitness).
    """
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)
    mode = "ab" if append else "wb"
    stderr_target = asyncio.subprocess.DEVNULL if suppress_stderr else asyncio.subprocess.STDOUT
    with open(stream_path, mode) as f:
        proc = await asyncio.create_subprocess_exec(
            args[0],
            *args[1:],
            stdout=f,
            stderr=stderr_target,
            cwd=cwd,
            env=proc_env,
        )
        if job_id is not None:
            RUNNING_JOBS[job_id] = proc
        try:
            try:
                returncode = await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                f.write(b"\n[Tool timed out.]\n")
                return -1
            return returncode or 0
        finally:
            if job_id is not None and job_id in RUNNING_JOBS:
                del RUNNING_JOBS[job_id]
