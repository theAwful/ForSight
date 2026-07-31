"""Shodan recon runner — query Shodan host API for each ROE IP.

Writes one text file per IP under results_dir/shodan/, e.g.:
  shodan/203.0.113.10.txt
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import List, Optional

import requests

from app.config import settings

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
# Free-tier friendly pacing between host lookups
REQUEST_GAP_SEC = 1.1


def _safe_ip_filename(ip: str) -> str:
    """Filesystem-safe name for an IP (IPv6-friendly)."""
    return ip.strip().replace(":", "_").replace("/", "_") + ".txt"


def _format_host_report(ip: str, data: dict) -> str:
    """Human-readable Shodan host report."""
    lines: list[str] = [
        f"Shodan host report: {ip}",
        "=" * 60,
        f"IP:            {data.get('ip_str') or ip}",
        f"Organization:  {data.get('org') or '—'}",
        f"ISP:           {data.get('isp') or '—'}",
        f"ASN:           {data.get('asn') or '—'}",
        f"OS:            {data.get('os') or '—'}",
        f"Country:       {data.get('country_name') or data.get('country_code') or '—'}",
        f"City:          {data.get('city') or '—'}",
        f"Last update:   {data.get('last_update') or '—'}",
    ]

    hostnames = data.get("hostnames") or []
    if hostnames:
        lines.append("Hostnames:     " + ", ".join(hostnames))

    domains = data.get("domains") or []
    if domains:
        lines.append("Domains:       " + ", ".join(domains))

    tags = data.get("tags") or []
    if tags:
        lines.append("Tags:          " + ", ".join(tags))

    vulns = data.get("vulns") or []
    if vulns:
        lines.append("")
        lines.append("Vulnerabilities:")
        for v in sorted(vulns):
            lines.append(f"  - {v}")

    ports = data.get("ports") or []
    if ports:
        lines.append("")
        lines.append(f"Open ports ({len(ports)}): " + ", ".join(str(p) for p in sorted(ports)))

    services = data.get("data") or []
    if services:
        lines.append("")
        lines.append("Services")
        lines.append("-" * 60)
        for svc in services:
            port = svc.get("port")
            transport = svc.get("transport") or "tcp"
            product = svc.get("product") or ""
            version = svc.get("version") or ""
            module = (svc.get("_shodan") or {}).get("module") or svc.get("product") or ""
            banner = (svc.get("data") or "").strip()
            header = f"[{port}/{transport}]"
            if product or version:
                header += f" {product} {version}".rstrip()
            elif module:
                header += f" {module}"
            lines.append(header)
            if banner:
                # Cap banner length so files stay readable
                snippet = banner if len(banner) <= 2000 else banner[:2000] + "\n… [banner truncated]"
                for bline in snippet.splitlines():
                    lines.append(f"  {bline}")
            lines.append("")

    lines.append("")
    lines.append("Raw JSON")
    lines.append("-" * 60)
    lines.append(json.dumps(data, indent=2, ensure_ascii=False))
    lines.append("")
    return "\n".join(lines)


def _format_error_report(ip: str, status: int, detail: str) -> str:
    return (
        f"Shodan host report: {ip}\n"
        f"{'=' * 60}\n"
        f"Status: {status}\n"
        f"Detail: {detail}\n"
    )


def _query_host(ip: str, api_key: str) -> tuple[int, str]:
    """Synchronous Shodan host lookup. Returns (http_status, file_body)."""
    try:
        resp = requests.get(
            SHODAN_HOST_URL.format(ip=ip),
            params={"key": api_key},
            timeout=30,
        )
    except requests.RequestException as exc:
        return 0, _format_error_report(ip, 0, f"Request failed: {exc}")

    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            return 200, _format_error_report(ip, 200, "Invalid JSON response from Shodan")
        return 200, _format_host_report(ip, data if isinstance(data, dict) else {"raw": data})

    if resp.status_code == 404:
        return 404, _format_error_report(ip, 404, "No information available for this IP in Shodan")

    detail = resp.text.strip()[:500] or resp.reason or "Unknown error"
    return resp.status_code, _format_error_report(ip, resp.status_code, detail)


async def run_recon_shodan(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    shodan_dir = results_dir / "shodan"
    shodan_dir.mkdir(parents=True, exist_ok=True)

    def _stream(msg: str) -> None:
        if not stream_path:
            return
        stream_path.parent.mkdir(parents=True, exist_ok=True)
        with open(stream_path, "a", encoding="utf-8") as f:
            f.write(msg)

    api_key = (settings.shodan_api_key or "").strip()
    if not api_key:
        msg = (
            "# Shodan skipped — FORSIGHT_SHODAN_API_KEY is not set.\n"
            "# Add your API key to the backend .env and restart.\n"
        )
        _stream(msg)
        (shodan_dir / "_skipped.txt").write_text(msg, encoding="utf-8")
        return 0, "", msg, stream_path or shodan_dir

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_ips: list[str] = []
    for ip in ips or []:
        ip = (ip or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        unique_ips.append(ip)

    if not unique_ips:
        msg = "# No IPs in ROE for Shodan.\n"
        _stream(msg)
        (shodan_dir / "_empty.txt").write_text(msg, encoding="utf-8")
        return 0, "", msg, stream_path or shodan_dir

    _stream(f"=== Shodan ===\nQuerying {len(unique_ips)} IP(s) → {shodan_dir}/\n")

    ok = 0
    missing = 0
    errors = 0
    last_code = 0

    for i, ip in enumerate(unique_ips):
        _stream(f"[{i + 1}/{len(unique_ips)}] {ip} … ")
        status, body = await asyncio.to_thread(_query_host, ip, api_key)
        out_file = shodan_dir / _safe_ip_filename(ip)
        out_file.write_text(body, encoding="utf-8")

        if status == 200:
            ok += 1
            _stream(f"ok → {out_file.name}\n")
        elif status == 404:
            missing += 1
            _stream(f"no data → {out_file.name}\n")
        else:
            errors += 1
            last_code = 1
            _stream(f"error {status} → {out_file.name}\n")

        if i < len(unique_ips) - 1:
            await asyncio.sleep(REQUEST_GAP_SEC)

    summary = (
        f"\nDone. {ok} with data, {missing} not found, {errors} errors. "
        f"Files in shodan/\n"
    )
    _stream(summary)
    (shodan_dir / "_summary.txt").write_text(
        f"Shodan run for project {project_id}\n"
        f"IPs queried: {len(unique_ips)}\n"
        f"With data: {ok}\n"
        f"Not found: {missing}\n"
        f"Errors: {errors}\n"
        f"Finished: {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
        encoding="utf-8",
    )
    return last_code, "", "", stream_path or shodan_dir
