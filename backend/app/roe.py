"""Parse ROE uploads: IPs and domain names from text, CSV, or JSON. Input sanitization for paste."""

import csv
import json
import re
from pathlib import Path
from typing import List, Tuple

# Max length for pasted ROE content
ROE_PASTE_MAX_LENGTH = 100_000


def sanitize_roe_input(content: str) -> str:
    """Sanitize pasted ROE: strip script tags, dangerous chars, control chars. No XSS/injection."""
    if not content or not isinstance(content, str):
        return ""
    # Truncate
    content = content[:ROE_PASTE_MAX_LENGTH]
    # Remove null bytes and control chars
    content = "".join(c for c in content if c.isprintable() or c in "\n\r\t")
    # Strip script/style tags and content between them
    content = re.sub(r"<script[^>]*>[\s\S]*?</script>", "", content, flags=re.IGNORECASE)
    content = re.sub(r"<style[^>]*>[\s\S]*?</style>", "", content, flags=re.IGNORECASE)
    content = re.sub(r"<[^>]+>", "", content)  # any remaining tags
    # Remove dangerous patterns that could break parsing or paths
    content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", content)
    return content.strip()


def _normalize_line(line: str) -> str:
    return line.strip().strip('"\'').strip()


def parse_txt(content: str) -> Tuple[List[str], List[str]]:
    """Parse plain text: one target per line. Returns (ips, domains)."""
    ips, domains = [], []
    for line in content.splitlines():
        s = _normalize_line(line)
        if not s or s.startswith("#"):
            continue
        # Heuristic: looks like IP/CIDR or hostname
        if re.match(r"^[\d./]+$", s) or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s):
            ips.append(s)
        else:
            domains.append(s)
    return ips, domains


def parse_csv(content: str) -> Tuple[List[str], List[str]]:
    """Parse CSV: look for columns named ip, domain, target, host, or first column."""
    ips, domains = [], []
    try:
        reader = csv.DictReader(content.splitlines())
        if not reader.fieldnames:
            return parse_txt(content)
        for row in reader:
            for key in ("ip", "domain", "target", "host", "address"):
                for k in row:
                    if k.lower() == key and row[k]:
                        v = _normalize_line(row[k])
                        if re.match(r"^[\d./]+$", v) or re.match(
                            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v
                        ):
                            ips.append(v)
                        else:
                            domains.append(v)
                        break
            if not any(k.lower() in ("ip", "domain", "target", "host", "address") for k in row):
                first = _normalize_line(next(iter(row.values()), ""))
                if first:
                    if re.match(r"^[\d./]+$", first) or re.match(
                        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", first
                    ):
                        ips.append(first)
                    else:
                        domains.append(first)
    except Exception:
        ips, domains = parse_txt(content)
    return ips, domains


def parse_json(content: str) -> Tuple[List[str], List[str]]:
    """Parse JSON: expect list of strings or { "ips": [], "domains": [] }."""
    ips, domains = [], []
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for x in data:
                s = str(x).strip()
                if re.match(r"^[\d./]+$", s) or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s):
                    ips.append(s)
                else:
                    domains.append(s)
        elif isinstance(data, dict):
            ips = [str(x).strip() for x in data.get("ips", data.get("ip", []))]
            domains = [str(x).strip() for x in data.get("domains", data.get("domain", []))]
    except Exception:
        ips, domains = parse_txt(content)
    return ips, domains


def parse_roe_content(content: str, filename: str = "") -> Tuple[List[str], List[str]]:
    """Dispatch by extension or content. Returns (ips, domains)."""
    ext = (Path(filename).suffix or "").lower()
    if ext == ".json":
        return parse_json(content)
    if ext == ".csv":
        return parse_csv(content)
    # .txt or unknown
    return parse_txt(content)
