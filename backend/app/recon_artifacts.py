"""Project recon artifact catalog — files produced by recon checklist runners."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

# Flat recon text/CSV artifacts (filename under results_dir)
RECON_FILES = [
    {
        "key": "whois",
        "label": "WHOIS",
        "description": "Domain registration / ownership",
        "runner_key": "recon_whois",
        "filename": "recon_whois.txt",
    },
    {
        "key": "subfinder",
        "label": "Subdomains",
        "description": "Subfinder subdomain enumeration",
        "runner_key": "recon_subfinder",
        "filename": "recon_subfinder.txt",
    },
    {
        "key": "amass",
        "label": "Amass",
        "description": "Passive DNS enumeration",
        "runner_key": "recon_amass",
        "filename": "recon_amass.txt",
    },
    {
        "key": "dnsrecon",
        "label": "DNS",
        "description": "dnsrecon records & zone transfer",
        "runner_key": "recon_dnsrecon",
        "filename": "recon_dnsrecon.txt",
    },
    {
        "key": "theharvester",
        "label": "OSINT",
        "description": "Emails, hosts, and names from theHarvester",
        "runner_key": "recon_theharvester",
        "filename": "recon_theharvester.txt",
    },
    {
        "key": "cloud",
        "label": "Cloud",
        "description": "Cloud object storage enumeration",
        "runner_key": "recon_cloud",
        "filename": "recon_cloud.txt",
    },
    {
        "key": "leaked",
        "label": "Leaked creds",
        "description": "DeHashed / leaked credential hits",
        "runner_key": "recon_leaked",
        "filename": "recon_dehashed.csv",
    },
]

SHODAN_DIR_NAME = "shodan"
SHODAN_META_PREFIX = "_"


def _file_meta(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        mtime = path.stat().st_mtime
    except OSError:
        size = 0
        mtime = None
    return {"size": size, "mtime": mtime, "available": size > 0}


def _job_fallback_path(results_dir: Path, runner_key: str) -> Optional[Path]:
    """
    Find the newest job_*.txt that starts with this runner's header.
    Used when a tool streamed only to the job log and never wrote its named artifact.
    """
    if not results_dir.is_dir():
        return None
    candidates: list[tuple[float, Path]] = []
    needle = f"=== {runner_key} ==="
    for path in results_dir.glob("job_*.txt"):
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:200]
        except OSError:
            continue
        if needle in head or f"=== {runner_key.replace('recon_', '')}" in head:
            try:
                candidates.append((path.stat().st_mtime, path))
            except OSError:
                continue
    if not candidates:
        # Broader match: whois jobs often header as "=== whois example.com ==="
        short = runner_key.replace("recon_", "")
        for path in results_dir.glob("job_*.txt"):
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:400]
            except OSError:
                continue
            if short in head.lower() and "=== " in head:
                try:
                    candidates.append((path.stat().st_mtime, path))
                except OSError:
                    continue
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def list_recon_artifacts(results_dir: Path) -> list[dict[str, Any]]:
    """Return catalog entries with availability metadata for the Recon UI."""
    items: list[dict[str, Any]] = []

    for spec in RECON_FILES:
        path = results_dir / spec["filename"]
        meta = _file_meta(path) if path.is_file() else {"size": 0, "mtime": None, "available": False}
        source = "file" if meta["available"] else None
        if not meta["available"]:
            fallback = _job_fallback_path(results_dir, spec["runner_key"])
            if fallback and fallback.is_file() and fallback.stat().st_size > 0:
                meta = _file_meta(fallback)
                source = "job"
        items.append({
            "key": spec["key"],
            "label": spec["label"],
            "description": spec["description"],
            "kind": "file",
            "available": bool(meta["available"]),
            "size": meta["size"],
            "mtime": meta["mtime"],
            "source": source,
            "children": [],
        })

    # Shodan folder — one child per IP file
    shodan_dir = results_dir / SHODAN_DIR_NAME
    children: list[dict[str, Any]] = []
    if shodan_dir.is_dir():
        for path in sorted(shodan_dir.glob("*.txt")):
            if path.name.startswith(SHODAN_META_PREFIX):
                continue
            child_meta = _file_meta(path)
            # Display name: filename without .txt, restore IPv6 colons where we replaced them
            label = path.stem
            children.append({
                "key": path.name,
                "label": label,
                "description": f"Shodan host report for {label}",
                "available": child_meta["available"],
                "size": child_meta["size"],
                "mtime": child_meta["mtime"],
            })

    items.insert(0, {
        "key": "shodan",
        "label": "Shodan",
        "description": "Internet-facing host intel per IP",
        "kind": "folder",
        "available": len(children) > 0,
        "size": sum(c["size"] for c in children),
        "mtime": max((c["mtime"] for c in children if c["mtime"]), default=None),
        "source": "dir" if children else None,
        "children": children,
    })

    return items


def resolve_recon_content(results_dir: Path, key: str, child: Optional[str] = None) -> tuple[str, str]:
    """
    Resolve recon artifact text content.
    Returns (label, content). Raises FileNotFoundError if missing.
    """
    if key == "shodan":
        if not child:
            raise FileNotFoundError("Specify a Shodan IP file")
        # Prevent path traversal
        safe = Path(child).name
        path = results_dir / SHODAN_DIR_NAME / safe
        if not path.is_file() or safe.startswith(SHODAN_META_PREFIX):
            raise FileNotFoundError(f"Shodan file not found: {child}")
        return safe, path.read_text(encoding="utf-8", errors="replace")

    spec = next((s for s in RECON_FILES if s["key"] == key), None)
    if not spec:
        raise FileNotFoundError(f"Unknown recon artifact: {key}")

    path = results_dir / spec["filename"]
    if path.is_file() and path.stat().st_size > 0:
        return spec["label"], path.read_text(encoding="utf-8", errors="replace")

    fallback = _job_fallback_path(results_dir, spec["runner_key"])
    if fallback and fallback.is_file():
        return spec["label"], fallback.read_text(encoding="utf-8", errors="replace")

    raise FileNotFoundError(f"No output yet for {spec['label']}")
