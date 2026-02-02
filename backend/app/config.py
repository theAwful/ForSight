"""Application configuration."""
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """ForSight settings from env or .env."""

    app_name: str = "ForSight"
    debug: bool = False
    # Auth: session secret (set FORSIGHT_SECRET_KEY in production)
    secret_key: str = "change-me-in-production-use-openssl-rand-hex-32"
    # Default user (override via env for production)
    default_username: str = "forsight"
    default_password_hash: str = ""  # If set, used instead of default forsight/forsight
    # Paths for uploads and scan output
    data_dir: Path = Path("data")
    uploads_dir: Path = Path("data/uploads")
    results_dir: Path = Path("data/results")
    # Tool paths (override via env if tools are not on PATH)
    nmap_path: str = "nmap"
    subfinder_path: str = "subfinder"
    testssl_path: str = "testssl.sh"
    sslscan_path: str = "sslscan"
    # Domain recon
    dnsrecon_path: str = "dnsrecon"
    amass_path: str = "amass"
    theharvester_path: str = "theHarvester"
    whois_path: str = "whois"
    # Cloud / CMS / web
    cloudenum_path: str = "cloud_enum"
    wpscan_path: str = "wpscan"
    droopescan_path: str = "droopescan"
    nuclei_path: str = "nuclei"
    nikto_path: str = "nikto"
    gowitness_path: str = "gowitness"
    masscan_path: str = "masscan"
    dirb_path: str = "dirb"
    dirb_wordlist: Optional[Path] = None  # default: data/wordlists/dirb-small.txt

    class Config:
        env_prefix = "FORSIGHT_"
        env_file = ".env"


settings = Settings()
