"""Tool runners for checklist phases. Each runner runs in its own job; tools in a section can run in parallel."""

from app.runners.cms import run_cms_enum
from app.runners.email_security import run_email_security
from app.runners.nmap_runner import run_nmap_ports, run_nmap_services
from app.runners.recon import (
    run_recon_amass,
    run_recon_cloud,
    run_recon_dnsrecon,
    run_recon_leaked,
    run_recon_subfinder,
    run_recon_theharvester,
    run_recon_whois,
)
from app.runners.legacy import (
    run_legacy_nmap,
    run_legacy_snmp,
    run_legacy_ftp,
    run_legacy_smb,
    run_legacy_banners,
    run_legacy_ldap,
)
from app.runners.ssl import run_ssl_enum
from app.runners.spray import run_password_spray
from app.runners.web_host import run_web_dirb, run_web_gowitness, run_web_nikto, run_web_nuclei

RUNNERS = {
    # Recon (per-tool)
    "recon_subfinder": run_recon_subfinder,
    "recon_dnsrecon": run_recon_dnsrecon,
    "recon_amass": run_recon_amass,
    "recon_theharvester": run_recon_theharvester,
    "recon_whois": run_recon_whois,
    "recon_cloud": run_recon_cloud,
    "recon_leaked": run_recon_leaked,
    # Enumeration
    "nmap_ports": run_nmap_ports,
    "nmap_services": run_nmap_services,
    "ssl_enum": run_ssl_enum,
    "legacy_nmap": run_legacy_nmap,
    "legacy_snmp": run_legacy_snmp,
    "legacy_ftp": run_legacy_ftp,
    "legacy_smb": run_legacy_smb,
    "legacy_banners": run_legacy_banners,
    "legacy_ldap": run_legacy_ldap,
    "email_security": run_email_security,
    # Web host (per-tool; CMS moved here)
    "web_nuclei": run_web_nuclei,
    "web_nikto": run_web_nikto,
    "web_dirb": run_web_dirb,
    "web_gowitness": run_web_gowitness,
    "cms_enum": run_cms_enum,
    "password_spray": run_password_spray,
}


def get_runner(runner_key: str):
    return RUNNERS.get(runner_key)
