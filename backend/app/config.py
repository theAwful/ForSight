"""Application configuration."""
from pathlib import Path
from typing import Optional

from pydantic import model_validator
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
    # Nessus Pro (local) or Tenable.io – Nessus tab works when keys or username/password are set.
    # Nessus Pro: default below. Two auth options:
    #   1) API keys: Nessus UI → My Account → API Keys (FORSIGHT_TENABLE_ACCESS_KEY, FORSIGHT_TENABLE_SECRET_KEY).
    #   2) Session: FORSIGHT_TENABLE_USERNAME + FORSIGHT_TENABLE_PASSWORD (POST /session → X-Cookie token); works for launch etc.
    # Nessus Pro API is at root (https://127.0.0.1:8834). If 404s, client tries .../api.
    # Tenable.io (cloud): set FORSIGHT_TENABLE_BASE_URL=https://cloud.tenable.com and use API keys.
    tenable_base_url: str = "https://127.0.0.1:8834"
    tenable_access_key: Optional[str] = None
    tenable_secret_key: Optional[str] = None
    tenable_username: Optional[str] = None
    tenable_password: Optional[str] = None
    tenable_verify_ssl: bool = False  # Set true for production; false skips verification (e.g. Nessus Pro self-signed)
    # CORS: comma-separated extra origins (e.g. https://app.example.com). Defaults include localhost:5173, 3000, 8080.
    cors_origins: Optional[str] = None
    # When true, allow browser Origin matching RFC1918 + localhost (HTTPS or HTTP, any port). Handy for https://<LAN-IP>.
    trust_lan_cors: bool = False
    # Optional regex (e.g. ^https://(app\.example\.com|10\.0\.0\.5)(:\\d+)?$) — overrides trust_lan_cors pattern when set.
    cors_origin_regex: Optional[str] = None
    # Session cookie Secure flag — use true when the app is only used over HTTPS (e.g. nginx TLS).
    session_https_only: bool = False
    # Built MkDocs site directory (index under this path). If unset, backend checks /app/site (Docker) then backend/site.
    docs_site_dir: Optional[Path] = None

    class Config:
        env_prefix = "FORSIGHT_"
        env_file = ".env"

    @model_validator(mode="after")
    def anchor_uploads_and_results_under_data_dir(self):
        """If uploads/results are left as relative paths, place them under data_dir (needed for systemd + FORSIGHT_DATA_DIR)."""
        root = self.data_dir
        if not self.uploads_dir.is_absolute():
            self.uploads_dir = root / "uploads"
        if not self.results_dir.is_absolute():
            self.results_dir = root / "results"
        return self


settings = Settings()
