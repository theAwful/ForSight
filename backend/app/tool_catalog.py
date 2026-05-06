"""Tool catalog: maps tool keys to config attributes and version-check flags.

Used by the Tool Management API (/api/tools/status) to surface which tools
are installed, their resolved binary path, and their reported version.
"""

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ToolCatalogEntry:
    display_name: str
    config_attr: str          # attribute name on the Settings object
    version_flags: List[str]  # flags to pass to the binary to get version output


TOOL_CATALOG: dict[str, ToolCatalogEntry] = {
    "nmap":          ToolCatalogEntry("Nmap",            "nmap_path",          ["--version"]),
    "nuclei":        ToolCatalogEntry("Nuclei",           "nuclei_path",        ["-version"]),
    "subfinder":     ToolCatalogEntry("Subfinder",        "subfinder_path",     ["-version"]),
    "dnsrecon":      ToolCatalogEntry("DNSRecon",         "dnsrecon_path",      ["--version"]),
    "amass":         ToolCatalogEntry("Amass",            "amass_path",         ["version"]),
    "theharvester":  ToolCatalogEntry("theHarvester",     "theharvester_path",  ["--version"]),
    "nikto":         ToolCatalogEntry("Nikto",            "nikto_path",         ["-Version"]),
    "dirb":          ToolCatalogEntry("Dirb",             "dirb_path",          []),   # no --version flag
    "gowitness":     ToolCatalogEntry("Gowitness",        "gowitness_path",     ["version"]),
    "wpscan":        ToolCatalogEntry("WPScan",           "wpscan_path",        ["--version"]),
    "droopescan":    ToolCatalogEntry("Droopescan",       "droopescan_path",    ["--version"]),
    "sslscan":       ToolCatalogEntry("SSLScan",          "sslscan_path",       ["--version"]),
    "testssl":       ToolCatalogEntry("testssl.sh",       "testssl_path",       ["--version"]),
    "whois":         ToolCatalogEntry("Whois",            "whois_path",         ["--version"]),
    "masscan":       ToolCatalogEntry("Masscan",          "masscan_path",       ["--version"]),
    "cloudenum":     ToolCatalogEntry("CloudEnum",        "cloudenum_path",     ["--help"]),
    "snmpwalk":      ToolCatalogEntry("snmpwalk",         "snmpwalk_path",      ["--version"]),
    "smbclient":     ToolCatalogEntry("smbclient",        "smbclient_path",     ["--version"]),
    "enum4linux":    ToolCatalogEntry("enum4linux",       "enum4linux_path",    []),   # no --version; existence check only
    "ldapsearch":    ToolCatalogEntry("ldapsearch",       "ldapsearch_path",    ["--version"]),
}


def check_tool_status(key: str) -> dict:
    """
    Check the health of a single tool by key.

    Returns a dict with:
        key, display_name, configured_path, resolved_path,
        version_string, version_error, status
    where status is 'found' | 'not_found' | 'error'.

    This function is synchronous (uses subprocess.run with timeout).
    The version check subprocess is spawned as an arg array — never via shell=True.
    """
    # Local import to avoid circular dependency at module load time
    from app.config import settings

    if key not in TOOL_CATALOG:
        return {
            "key": key,
            "display_name": key,
            "configured_path": key,
            "resolved_path": None,
            "version_string": None,
            "version_error": f"Unknown tool key: {key!r}",
            "status": "not_found",
        }

    entry = TOOL_CATALOG[key]
    configured_path: str = getattr(settings, entry.config_attr, None) or key

    # 1. Resolve the binary
    resolved: Optional[str] = shutil.which(configured_path)
    if resolved is None:
        return {
            "key": key,
            "display_name": entry.display_name,
            "configured_path": configured_path,
            "resolved_path": None,
            "version_string": None,
            "version_error": f"{configured_path!r}: command not found",
            "status": "not_found",
        }

    # 2. Run the version check (if the tool has version flags)
    version_string: Optional[str] = None
    version_error: Optional[str] = None

    if entry.version_flags:
        try:
            result = subprocess.run(
                [configured_path] + entry.version_flags,
                capture_output=True,
                text=True,
                timeout=5,
            )
            raw_output = (result.stdout + result.stderr).strip()
            # First non-empty line, capped at 200 chars
            first_line = next((ln for ln in raw_output.splitlines() if ln.strip()), raw_output)
            version_string = first_line[:200] if first_line else "(no output)"
        except subprocess.TimeoutExpired:
            version_error = "Version check timed out (>5s)"
        except FileNotFoundError:
            version_error = f"{configured_path!r}: not found when running version check"
        except Exception as exc:
            version_error = str(exc)[:200]

    status = "found" if version_error is None else "error"

    return {
        "key": key,
        "display_name": entry.display_name,
        "configured_path": configured_path,
        "resolved_path": resolved,
        "version_string": version_string,
        "version_error": version_error,
        "status": status,
    }


def check_all_tools() -> list[dict]:
    """Check status of every tool in the catalog. Returns list of ToolStatus dicts."""
    return [check_tool_status(key) for key in TOOL_CATALOG]


def update_tool_path(key: str, new_path: str) -> None:
    """Update the in-memory configured path for a tool. Does NOT write to disk."""
    from app.config import settings
    if key not in TOOL_CATALOG:
        raise KeyError(f"Unknown tool key: {key!r}")
    entry = TOOL_CATALOG[key]
    setattr(settings, entry.config_attr, new_path)
