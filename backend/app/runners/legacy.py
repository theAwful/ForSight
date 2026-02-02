"""Legacy/insecure protocol enumeration: SMTP, SNMP, FTP, LDAP, DNS, DHCP, SMB, Telnet, SSH.

Split into separate runners so each protocol can run as its own job (more parallel workers).
- legacy_nmap: nmap -sC -sV on legacy ports
- legacy_snmp: snmpwalk (default community strings)
- legacy_ftp: FTP anonymous login
- legacy_smb: smbclient -N -L, enum4linux
- legacy_banners: SMTP/Telnet/SSH banner grab
- legacy_ldap: ldapsearch -x
"""

import asyncio
from pathlib import Path
from typing import List, Optional

from app.config import settings
from app.nmap_parse import get_hosts_for_ports, get_ports_by_host, nmap_output_exists
from app.runners.base import run_tool, run_tool_stream

# Ports for legacy protocols (used by get_hosts_for_ports and nmap script scan)
LEGACY_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS (TCP)
    67,   # DHCP (server)
    68,   # DHCP (client)
    139,  # NetBIOS/SMB
    161,  # SNMP
    162,  # SNMP trap
    389,  # LDAP
    445,  # SMB
    587,  # SMTP submission
    636,  # LDAPS
]


async def _banner_grab(host: str, port: int, timeout: float = 5.0) -> str:
    """Connect and read initial banner (first line or ~512 bytes)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            return data.decode("utf-8", errors="replace").strip() or "(no banner)"
        finally:
            writer.close()
            await writer.wait_closed()
    except Exception as e:
        return f"(error: {e})"


def _no_nmap_msg(out_name: str) -> str:
    return f"# Run Nmap first so legacy protocol targets can be discovered.\n"


async def run_legacy_nmap(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """Run nmap -sC -sV on legacy ports for each host that has any legacy port open (from nmap results)."""
    if not nmap_output_exists(results_dir):
        msg = _no_nmap_msg("legacy_nmap")
        out = results_dir / "legacy_nmap.txt"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out

    by_host = get_ports_by_host(results_dir)
    legacy_set = set(LEGACY_PORTS)
    hosts_ports: dict[str, list[int]] = {}
    for host, ports in by_host.items():
        open_legacy = [p for p in ports if p in legacy_set]
        if open_legacy:
            hosts_ports[host] = sorted(open_legacy)

    if not hosts_ports:
        msg = "# No legacy ports (FTP/SSH/Telnet/SMTP/SNMP/LDAP/SMB/DNS/DHCP) found by Nmap.\n"
        out = results_dir / "legacy_nmap.txt"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out

    output_path = results_dir / "legacy_nmap.txt"
    all_stdout: List[str] = []
    last_code = 0
    for host, ports in list(hosts_ports.items())[:50]:
        port_list = ",".join(str(p) for p in ports)
        args = [
            settings.nmap_path,
            "-sC", "-sV", "-T4",
            "-p", port_list,
            "--open",
            host,
        ]
        section = f"\n=== nmap -sC -sV -p {port_list} {host} ===\n"
        if stream_path:
            with open(stream_path, "a", encoding="utf-8") as f:
                f.write(section)
        if stream_path is not None:
            code = await run_tool_stream(args, stream_path, job_id=job_id, append=True, timeout=600)
        else:
            code, stdout, stderr = await run_tool("nmap_legacy", args, output_path=None, timeout=600)
            all_stdout.append(section + stdout + ("\n" + stderr if stderr else ""))
        if code != 0:
            last_code = code
    if stream_path is None and output_path:
        output_path.write_text("\n".join(all_stdout))
    return last_code, "", "", stream_path or output_path


async def _run_legacy_protocol(
    results_dir: Path,
    stream_path: Optional[Path],
    job_id: Optional[int],
    out_filename: str,
    title: str,
    run_fn,  # async (append, stream_path, job_id) -> int
) -> tuple[int, str, str, Optional[Path]]:
    """Shared pattern: check nmap, run protocol logic, write to out_filename."""
    if not nmap_output_exists(results_dir):
        msg = _no_nmap_msg(out_filename)
        out = results_dir / out_filename
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out

    output_path = results_dir / out_filename
    lines: List[str] = []

    def append(msg: str) -> None:
        lines.append(msg)
        if stream_path:
            with open(stream_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

    append(title + "\n")
    last_code = await run_fn(append, stream_path, job_id)
    if stream_path is None and output_path:
        output_path.write_text("\n".join(lines))
    return last_code, "", "", stream_path or output_path


async def run_legacy_snmp(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """SNMP: snmpwalk with default community strings on 161/162."""
    async def do(append, sp, jid):
        last_code = 0
        hosts = get_hosts_for_ports(results_dir, [161, 162])
        if not hosts:
            append("# No SNMP ports (161/162) found by Nmap.\n")
            return last_code
        try:
            for hp in hosts[:20]:
                host, port = hp.split(":", 1)
                port = int(port)
                for community in ("public", "private"):
                    args = ["snmpwalk", "-v2c", "-c", community, "-t", "3", f"{host}:{port}", "system"]
                    append(f"--- {host}:{port} community={community} ---")
                    if sp is not None:
                        code = await run_tool_stream(args, sp, job_id=jid, append=True, timeout=30)
                    else:
                        code, stdout, stderr = await run_tool("snmpwalk", args, output_path=None, timeout=30)
                        append(stdout or stderr or "")
                    if code != 0:
                        last_code = code
        except FileNotFoundError:
            append("(snmpwalk not installed or not on PATH)\n")
        return last_code

    return await _run_legacy_protocol(
        results_dir, stream_path, job_id, "legacy_snmp.txt",
        "=== SNMP (snmpwalk, default community strings) ===",
        do,
    )


async def run_legacy_ftp(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """FTP: anonymous login on port 21."""
    async def do(append, sp, jid):
        last_code = 0
        hosts = get_hosts_for_ports(results_dir, [21])
        if not hosts:
            append("# No FTP port (21) found by Nmap.\n")
            return last_code
        try:
            for hp in hosts[:20]:
                host, port = hp.split(":", 1)
                port = int(port)
                append(f"--- {host}:{port} ---")
                args = ["curl", "-s", "-u", "anonymous:", f"ftp://{host}:{port}/", "--connect-timeout", "5", "-m", "15"]
                if sp is not None:
                    code = await run_tool_stream(args, sp, job_id=jid, append=True, timeout=20)
                else:
                    code, stdout, stderr = await run_tool("curl_ftp", args, output_path=None, timeout=20)
                    append(stdout or stderr or "(no output)")
                if code != 0:
                    last_code = code
        except FileNotFoundError:
            append("(curl not installed or not on PATH)\n")
        return last_code

    return await _run_legacy_protocol(
        results_dir, stream_path, job_id, "legacy_ftp.txt",
        "=== FTP anonymous login ===",
        do,
    )


async def run_legacy_smb(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """SMB: smbclient -N -L and enum4linux on 139/445."""
    async def do(append, sp, jid):
        last_code = 0
        hosts_raw = get_hosts_for_ports(results_dir, [139, 445])
        if not hosts_raw:
            append("# No SMB ports (139/445) found by Nmap.\n")
            return last_code
        hosts_only = list(dict.fromkeys(hp.split(":", 1)[0] for hp in hosts_raw))[:15]
        try:
            for host in hosts_only:
                append(f"--- {host} ---")
                args_smb = ["smbclient", "-N", "-L", f"//{host}", "-t", "5"]
                if sp is not None:
                    code = await run_tool_stream(args_smb, sp, job_id=jid, append=True, timeout=30)
                else:
                    code, stdout, stderr = await run_tool("smbclient", args_smb, output_path=None, timeout=30)
                    append(stdout or stderr or "")
                if code != 0:
                    last_code = code
                try:
                    args_enum = ["enum4linux", "-a", host]
                    if sp is not None:
                        await run_tool_stream(args_enum, sp, job_id=jid, append=True, timeout=120)
                    else:
                        c, so, se = await run_tool("enum4linux", args_enum, output_path=None, timeout=120)
                        append(so or se or "")
                except FileNotFoundError:
                    append("(enum4linux not installed)\n")
        except FileNotFoundError:
            append("(smbclient not installed or not on PATH)\n")
        return last_code

    return await _run_legacy_protocol(
        results_dir, stream_path, job_id, "legacy_smb.txt",
        "=== SMB (smbclient -N -L, enum4linux) ===",
        do,
    )


async def run_legacy_banners(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """Banner grab: SMTP (25/587), Telnet (23), SSH (22)."""
    if not nmap_output_exists(results_dir):
        msg = _no_nmap_msg("legacy_banners")
        out = results_dir / "legacy_banners.txt"
        if stream_path:
            stream_path.write_text(msg)
        out.write_text(msg)
        return 0, "", "", stream_path or out

    output_path = results_dir / "legacy_banners.txt"
    lines: List[str] = []

    def append(msg: str) -> None:
        lines.append(msg)
        if stream_path:
            with open(stream_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

    for name, port_list in [
        ("SMTP", [25, 587]),
        ("Telnet", [23]),
        ("SSH", [22]),
    ]:
        hosts = get_hosts_for_ports(results_dir, port_list)
        if not hosts:
            continue
        append(f"\n=== {name} banner grab ===")
        for hp in hosts[:15]:
            host, port = hp.split(":", 1)
            port = int(port)
            banner = await _banner_grab(host, port)
            append(f"{host}:{port} -> {banner[:200]}")

    if not lines:
        append("# No SMTP/Telnet/SSH ports found by Nmap.\n")
    if stream_path is None and output_path:
        output_path.write_text("\n".join(lines))
    return 0, "", "", stream_path or output_path


async def run_legacy_ldap(
    project_id: int,
    ips: List[str],
    domains: List[str],
    results_dir: Path,
    stream_path: Optional[Path] = None,
    job_id: Optional[int] = None,
    **kwargs,
) -> tuple[int, str, str, Optional[Path]]:
    """LDAP: ldapsearch -x on 389/636."""
    async def do(append, sp, jid):
        last_code = 0
        hosts = get_hosts_for_ports(results_dir, [389, 636])
        if not hosts:
            append("# No LDAP ports (389/636) found by Nmap.\n")
            return last_code
        try:
            for hp in hosts[:15]:
                host, port = hp.split(":", 1)
                port = int(port)
                append(f"--- {host}:{port} ---")
                args = ["ldapsearch", "-x", "-H", f"ldap://{host}:{port}", "-b", "", "-s", "base", "-LLL", "-t", "5"]
                if sp is not None:
                    code = await run_tool_stream(args, sp, job_id=jid, append=True, timeout=15)
                else:
                    code, stdout, stderr = await run_tool("ldapsearch", args, output_path=None, timeout=15)
                    append(stdout or stderr or "")
                if code != 0:
                    last_code = code
        except FileNotFoundError:
            append("(ldapsearch not installed or not on PATH)\n")
        return last_code

    return await _run_legacy_protocol(
        results_dir, stream_path, job_id, "legacy_ldap.txt",
        "=== LDAP (ldapsearch -x) ===",
        do,
    )
