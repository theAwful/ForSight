"""Checklist definition for external pentest phases (from ROE-driven workflow)."""

from enum import Enum
from typing import Optional


class Phase(str, Enum):
    PRE_ENGAGEMENT = "pre_engagement"
    RECON = "recon"
    NMAP = "nmap"
    ENUMERATION = "enumeration"
    WEB_HOST = "web_host"
    REPORTING = "reporting"


# Phases that require Nmap results before Run all / individual runners are enabled
PHASES_REQUIRING_NMAP = {Phase.ENUMERATION, Phase.WEB_HOST}

# Both must be checklist "completed" before any scan jobs can run (API-enforced)
PRE_ENGAGEMENT_GATE_ITEM_IDS = ("roe_scope", "roe_comm")


class ChecklistItem:
    """Single checklist item with id, phase, description, and optional runner key."""

    def __init__(
        self,
        id: str,
        phase: Phase,
        description: str,
        runner_key: Optional[str] = None,
        tools: Optional[list[str]] = None,
    ):
        self.id = id
        self.phase = phase
        self.description = description
        self.runner_key = runner_key
        self.tools = tools or []


CHECKLIST = [
    # 1. Pre-engagement
    ChecklistItem("roe_scope", Phase.PRE_ENGAGEMENT, "Scope verified", runner_key=None),
    ChecklistItem("roe_comm", Phase.PRE_ENGAGEMENT, "Client notified", runner_key=None),
    # 2. Recon — domains only; no Nmap required (description = service area; tools listed in UI)
    ChecklistItem("recon_subfinder", Phase.RECON, "Subdomains", runner_key="recon_subfinder", tools=["subfinder"]),
    ChecklistItem("recon_dnsrecon", Phase.RECON, "DNS reconnaissance", runner_key="recon_dnsrecon", tools=["dnsrecon"]),
    ChecklistItem("recon_amass", Phase.RECON, "DNS enumeration", runner_key="recon_amass", tools=["amass"]),
    ChecklistItem("recon_theharvester", Phase.RECON, "OSINT & emails", runner_key="recon_theharvester", tools=["theHarvester"]),
    ChecklistItem("recon_whois", Phase.RECON, "WHOIS", runner_key="recon_whois", tools=["whois"]),
    ChecklistItem("recon_cloud", Phase.RECON, "Cloud object storage", runner_key="recon_cloud", tools=["CloudEnum"]),
    ChecklistItem("recon_leaked", Phase.RECON, "Leaked credentials", runner_key="recon_leaked", tools=["Dehashed", "H8mail", "TCM"]),
    # 3. Nmap
    ChecklistItem("enum_nmap_tcp_udp", Phase.NMAP, "Port discovery", runner_key="nmap_ports", tools=["nmap"]),
    ChecklistItem("enum_fingerprint", Phase.NMAP, "Service fingerprinting", runner_key="nmap_services", tools=["nmap"]),
    # 4. Enumeration — requires Nmap
    ChecklistItem("enum_ssl", Phase.ENUMERATION, "SSL / TLS", runner_key="ssl_enum", tools=["testssl.sh", "sslscan"]),
    ChecklistItem("enum_vpn", Phase.ENUMERATION, "VPN gateways", runner_key=None),
    ChecklistItem("enum_vpn_exposure", Phase.ENUMERATION, "VPN exposure", runner_key=None),
    ChecklistItem("enum_legacy_nmap", Phase.ENUMERATION, "Legacy services", runner_key="legacy_nmap", tools=["nmap"]),
    ChecklistItem("enum_legacy_snmp", Phase.ENUMERATION, "SNMP", runner_key="legacy_snmp", tools=["snmpwalk"]),
    ChecklistItem("enum_legacy_ftp", Phase.ENUMERATION, "FTP", runner_key="legacy_ftp", tools=["curl"]),
    ChecklistItem("enum_legacy_smb", Phase.ENUMERATION, "SMB", runner_key="legacy_smb", tools=["smbclient", "enum4linux"]),
    ChecklistItem("enum_legacy_banners", Phase.ENUMERATION, "Mail & remote banners", runner_key="legacy_banners", tools=[]),
    ChecklistItem("enum_legacy_ldap", Phase.ENUMERATION, "LDAP", runner_key="legacy_ldap", tools=["ldapsearch"]),
    ChecklistItem("enum_email", Phase.ENUMERATION, "Email authentication", runner_key="email_security", tools=["Domain Security Scanner"]),
    # 5. Web host — requires Nmap
    ChecklistItem("web_nuclei", Phase.WEB_HOST, "Web vulnerability scan", runner_key="web_nuclei", tools=["nuclei"]),
    ChecklistItem("web_nikto", Phase.WEB_HOST, "Web server audit", runner_key="web_nikto", tools=["nikto"]),
    ChecklistItem("web_dirb", Phase.WEB_HOST, "Directory brute-force", runner_key="web_dirb", tools=["dirb"]),
    ChecklistItem("web_gowitness", Phase.WEB_HOST, "Screenshots", runner_key="web_gowitness", tools=["gowitness"]),
    ChecklistItem("web_cms", Phase.WEB_HOST, "CMS assessment", runner_key="cms_enum", tools=["wpscan", "droopescan", "CMSeek"]),
    # Exploitation (password spray) omitted from v1 checklist
]


def get_checklist_by_phase():
    by_phase = {}
    for item in CHECKLIST:
        by_phase.setdefault(item.phase.value, []).append(
            {"id": item.id, "description": item.description, "runner_key": item.runner_key, "tools": item.tools}
        )
    return by_phase


def get_item(item_id: str) -> Optional[ChecklistItem]:
    for item in CHECKLIST:
        if item.id == item_id:
            return item
    return None


def get_item_id_by_runner_key(runner_key: str) -> Optional[str]:
    for item in CHECKLIST:
        if item.runner_key == runner_key:
            return item.id
    return None


def get_runner_keys_for_phase(phase: Phase) -> list[str]:
    """Return list of runner_keys in a phase (for Run all)."""
    return [item.runner_key for item in CHECKLIST if item.phase == phase and item.runner_key]
