"""Web host enumeration: nuclei, nikto, gowitness, dirb (each runs in its own job)."""

import json
import re
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from app.config import settings
from app.runners.base import run_tool_stream
from app.runners.web_urls import get_web_urls


def _parse_url_for_nikto(url: str) -> Tuple[str, int, bool]:
    """Return (host, port, use_ssl) for nikto -h host -p port -ssl."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    return host, port, use_ssl


def _safe_filename(url: str) -> str:
    s = re.sub(r"https?://", "", url)
    s = re.sub(r"[^a-zA-Z0-9._-]", "_", s)
    return (s[:80] + ".png") if len(s) > 80 else s + ".png"


async def _write_header(stream_path: Optional[Path], msg: str) -> None:
    if stream_path:
        stream_path.parent.mkdir(parents=True, exist_ok=True)
        with open(stream_path, "a") as f:
            f.write(msg + "\n")


async def run_web_nuclei(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    use_nmap: bool = False,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    urls = await get_web_urls(project_id, ips, domains, results_dir, use_nmap=use_nmap)
    if not urls:
        await _write_header(stream_path, "# No web URLs (add domains/IPs or run masscan).")
        out = results_dir / "web_nuclei.txt"
        out.write_text("# No web URLs.\n")
        return 0, "", "", stream_path or out
    urls_file = results_dir / "web_host_urls.txt"
    urls_file.write_text("\n".join(urls))
    nuclei_json = results_dir / "web_nuclei.json"
    await _write_header(stream_path, "=== nuclei ===")
    # nuclei -l targets -json-export output.json
    args = [
        settings.nuclei_path,
        "-l", str(urls_file),
        "-json-export", str(nuclei_json),
    ]
    code = await run_tool_stream(args, stream_path or (results_dir / "web_nuclei.txt"), job_id=job_id, append=True, timeout=1800)
    return code, "", "", stream_path or nuclei_json


async def run_web_nikto(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    use_nmap: bool = False,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    urls = await get_web_urls(project_id, ips, domains, results_dir, use_nmap=use_nmap)
    if not urls:
        await _write_header(stream_path, "# No web URLs.")
        return 0, "", "", stream_path
    nikto_out = results_dir / "web_nikto.txt"
    for url in urls[:10]:
        await _write_header(stream_path, f"--- nikto {url} ---")
        host, port, use_ssl = _parse_url_for_nikto(url)
        # -Format txt without -o causes "Output file format specified without a name"; write to stdout and we stream it
        args = [settings.nikto_path, "-h", host]
        if port not in (80, 443):
            args.extend(["-p", str(port)])
        if use_ssl:
            args.append("-ssl")
        await run_tool_stream(args, stream_path or nikto_out, job_id=job_id, append=True, timeout=300)
    return 0, "", "", stream_path or nikto_out


async def run_web_gowitness(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    use_nmap: bool = False,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    urls = await get_web_urls(project_id, ips, domains, results_dir, use_nmap=use_nmap)
    if not urls:
        await _write_header(stream_path, "# No web URLs.")
        return 0, "", "", stream_path
    screenshots_dir = results_dir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    urls_file = results_dir / "gowitness_urls.txt"
    urls_file.write_text("\n".join(urls[:100]))
    await _write_header(stream_path, "=== gowitness scan file ===")
    # gowitness scan file -f urls.txt -s /path/to/screenshots
    args = [
        settings.gowitness_path,
        "scan", "file",
        "-f", str(urls_file),
        "-s", str(screenshots_dir),
    ]
    # Don't suppress stderr so gowitness errors show in Output/Logs tab
    code = await run_tool_stream(args, stream_path, job_id=job_id, append=True, timeout=1800, suppress_stderr=False)
    manifest = []
    for p in sorted(screenshots_dir.glob("*")):
        if p.suffix.lower() not in (".png", ".jpg", ".jpeg"):
            continue
        stem = p.stem
        url = ""
        # New gowitness format: http---host-port or https---host-port (host can contain dots)
        m = re.match(r"^(https?)---(.+)-(\d+)$", stem)
        if m:
            scheme, host, port_str = m.group(1), m.group(2), m.group(3)
            port = int(port_str)
            if port in (80, 443):
                url = f"{scheme}://{host}"
            else:
                url = f"{scheme}://{host}:{port}"
        elif "_" in stem:
            # Old format: example.com_80 or https_example.com_443
            if stem.startswith("http"):
                scheme, rest = stem.split("_", 1)
                scheme = scheme + "://"
            else:
                scheme = "http://"
                rest = stem
            parts = rest.rsplit("_", 1)
            host_part = parts[0].replace("_", ".")
            port_part = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else (443 if "https" in scheme else 80)
            if port_part in (80, 443):
                url = f"{scheme}{host_part}"
            else:
                url = f"{scheme}{host_part}:{port_part}"
        manifest.append({"url": url, "filename": p.name})
    (screenshots_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return code, "", "", stream_path


def _dirb_wordlist() -> Path:
    """Path to small dirb wordlist (for testing)."""
    wl = getattr(settings, "dirb_wordlist", None)
    if wl is not None and wl.exists():
        return wl
    return settings.data_dir / "wordlists" / "dirb-small.txt"


async def run_web_dirb(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    use_nmap: bool = False,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """Directory busting with dirb; small wordlist, output streamed to job log."""
    urls = await get_web_urls(project_id, ips, domains, results_dir, use_nmap=use_nmap)
    if not urls:
        await _write_header(stream_path, "# No web URLs.")
        return 0, "", "", stream_path
    wordlist = _dirb_wordlist()
    if not wordlist.exists():
        await _write_header(stream_path, f"# Wordlist not found: {wordlist}")
        return 0, "", "", stream_path
    dirb_out = results_dir / "web_dirb.txt"
    for url in urls[:20]:
        await _write_header(stream_path, f"--- dirb {url} ---")
        args = [
            settings.dirb_path,
            url.rstrip("/") + "/",
            str(wordlist),
        ]
        code = await run_tool_stream(
            args,
            stream_path or dirb_out,
            job_id=job_id,
            append=True,
            timeout=600,
        )
    return 0, "", "", stream_path or dirb_out
