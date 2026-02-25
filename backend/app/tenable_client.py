"""Nessus Pro / Tenable API client.

Supports two auth modes:
  1) API keys: X-ApiKeys: accessKey=...; secretKey=... (Tenable.io or Nessus Pro with keys).
  2) Session: POST /session with username/password → X-Cookie: token=... (Nessus Pro; see e.g. nessus-automation).
Nessus Pro (local): https://127.0.0.1:8834 — API at root or /api depending on version.
Tenable.io (cloud): https://cloud.tenable.com
"""

from typing import Any, Dict, List, Optional

import requests
from urllib3.exceptions import ProtocolError

from app.config import settings

CONNECTION_ERROR_RETRIES = 2
CREATE_SCAN_TIMEOUT = 120

# Cached session token for username/password auth (cleared on 401).
_cached_session_token: Optional[str] = None


def _enabled() -> bool:
    return bool(
        (settings.tenable_access_key and settings.tenable_secret_key)
        or (settings.tenable_username and settings.tenable_password)
    )


def _use_session_auth() -> bool:
    return bool(settings.tenable_username and settings.tenable_password)


def _get_session_token() -> str:
    """POST /session with username/password; return token. Uses base URL as-is (no /api)."""
    global _cached_session_token
    if _cached_session_token:
        return _cached_session_token
    base = settings.tenable_base_url.rstrip("/")
    url = f"{base}/session"
    verify = settings.tenable_verify_ssl
    resp = requests.post(
        url,
        json={"username": settings.tenable_username, "password": settings.tenable_password},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=30,
        verify=verify,
    )
    if not resp.ok:
        raise TenableAPIError(
            f"Session login failed: {resp.status_code} {resp.reason}",
            status_code=resp.status_code,
            response_text=resp.text,
        )
    data = resp.json()
    token = data.get("token")
    if not token:
        raise TenableAPIError("Session response did not contain token", response_text=resp.text)
    _cached_session_token = token
    return token


def _clear_session_token() -> None:
    global _cached_session_token
    _cached_session_token = None


def _headers() -> Dict[str, str]:
    if _use_session_auth():
        token = _get_session_token()
        return {
            "X-Cookie": f"token={token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    return {
        "X-ApiKeys": f"accessKey={settings.tenable_access_key}; secretKey={settings.tenable_secret_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _base() -> str:
    return settings.tenable_base_url.rstrip("/")


def _alt_base() -> Optional[str]:
    """If base ends with /api, return base without it; else return base + /api. Used for 404 fallback."""
    b = _base()
    if b.endswith("/api"):
        return b.removesuffix("/api").rstrip("/") or None
    return f"{b}/api"


def _url(path: str, base_override: Optional[str] = None) -> str:
    base = (base_override or _base())
    path = path if path.startswith("/") else f"/{path}"
    return f"{base}{path}"


class TenableAPIError(Exception):
    """Tenable API returned an error. status_code and response body are set when available."""

    def __init__(self, message: str, status_code: Optional[int] = None, response_text: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


def _request(
    method: str,
    path: str,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    stream: bool = False,
    base_override: Optional[str] = None,
    timeout: int = 60,
    _retried_401: bool = False,
) -> requests.Response:
    if not _enabled():
        raise RuntimeError(
            "Tenable API is not configured (set FORSIGHT_TENABLE_ACCESS_KEY/SECRET_KEY or FORSIGHT_TENABLE_USERNAME/PASSWORD)"
        )
    url = _url(path, base_override=base_override)
    verify = settings.tenable_verify_ssl
    try:
        resp = requests.request(
            method,
            url,
            headers=_headers(),
            json=json_body,
            timeout=timeout,
            stream=stream,
            verify=verify,
        )
    except (requests.RequestException, ProtocolError, OSError) as e:
        raise TenableAPIError(str(e)) from e
    if not resp.ok:
        if resp.status_code == 401 and _use_session_auth() and not _retried_401:
            _clear_session_token()
            return _request(
                method, path,
                json_body=json_body, stream=stream, base_override=base_override, timeout=timeout,
                _retried_401=True,
            )
        msg = f"Tenable API error: {resp.status_code} {resp.reason}"
        try:
            body = resp.text
            if body:
                msg += f" — {body[:500]}"
        except Exception:
            pass
        raise TenableAPIError(msg, status_code=resp.status_code, response_text=resp.text)
    return resp


def is_configured() -> bool:
    """Return True if Tenable API keys are set."""
    return _enabled()


def list_scans() -> Dict[str, Any]:
    """GET /scans – list all scans (usable + manageable). Tries alt base on 404 (Nessus Pro with/without /api)."""
    try:
        r = _request("GET", "/scans")
        return r.json()
    except TenableAPIError as e:
        if e.status_code == 404:
            alt = _alt_base()
            if alt:
                r = _request("GET", "/scans", base_override=alt)
                return r.json()
        raise


def get_scan(scan_id: int) -> Dict[str, Any]:
    """GET /scans/{id} – scan details."""
    r = _request("GET", f"/scans/{scan_id}")
    return r.json()


def launch_scan(scan_id: int, alt_targets: Optional[List[str]] = None) -> Dict[str, Any]:
    """POST /scans/{id}/launch – launch scan. Optionally pass alt_targets (IPs/domains). Retries on connection errors."""
    body: Dict[str, Any] = {}
    if alt_targets:
        body["alt_targets"] = alt_targets
    last_err: Optional[Exception] = None
    bases_to_try: List[Optional[str]] = [None]
    alt = _alt_base()
    if alt:
        bases_to_try.append(alt)
    for base_override in bases_to_try:
        for attempt in range(CONNECTION_ERROR_RETRIES + 1):
            try:
                r = _request(
                    "POST",
                    f"/scans/{scan_id}/launch",
                    json_body=body if body else None,
                    timeout=CREATE_SCAN_TIMEOUT,
                    base_override=base_override,
                )
                return r.json()
            except TenableAPIError as e:
                if e.status_code and 400 <= (e.status_code or 0) < 500:
                    raise
                if e.status_code == 404 and base_override is None and alt:
                    break
                err_str = str(e).lower()
                if "incompleteread" in err_str or "connection" in err_str or "broken" in err_str:
                    last_err = e
                    if attempt < CONNECTION_ERROR_RETRIES:
                        continue
                raise
            except (ProtocolError, OSError, requests.RequestException) as e:
                last_err = e
                if attempt < CONNECTION_ERROR_RETRIES:
                    continue
                msg = str(e)
                if "incompleteread" in msg.lower() or "connection" in msg.lower():
                    msg = "Nessus closed the connection (IncompleteRead). Try again in a moment."
                raise TenableAPIError(msg) from e
    if last_err:
        raise TenableAPIError(str(last_err)) from last_err
    raise TenableAPIError("Launch scan failed after retries")


def export_scan(scan_id: int, format: str = "nessus") -> Dict[str, Any]:
    """POST /scans/{id}/export – request export. format: nessus, csv, html, pdf. Returns { file: <id> }."""
    r = _request("POST", f"/scans/{scan_id}/export", json_body={"format": format})
    return r.json()


def export_status(scan_id: int, file_id: int) -> Dict[str, Any]:
    """GET /scans/{id}/export/{file_id}/status – poll until status is 'ready'."""
    r = _request("GET", f"/scans/{scan_id}/export/{file_id}/status")
    return r.json()


def export_download(scan_id: int, file_id: int) -> bytes:
    """GET /scans/{id}/export/{file_id}/download – download exported file (bytes)."""
    r = _request("GET", f"/scans/{scan_id}/export/{file_id}/download", stream=True)
    return r.content


def get_scan_history(scan_id: int) -> Dict[str, Any]:
    """GET /scans/{id}/history – list history (past runs)."""
    r = _request("GET", f"/scans/{scan_id}/history")
    return r.json()


def list_templates(editor_type: str = "scan", base_override: Optional[str] = None) -> Dict[str, Any]:
    """GET /editor/{type}/templates – list scan templates (use template uuid when creating a scan)."""
    r = _request("GET", f"/editor/{editor_type}/templates", base_override=base_override)
    return r.json()


def list_policies(base_override: Optional[str] = None) -> Dict[str, Any]:
    """GET /policies – list scan policies (built-in and user-defined)."""
    r = _request("GET", "/policies", base_override=base_override)
    return r.json()


def list_templates_and_policies() -> Dict[str, Any]:
    """
    Return both scan templates and policies for the template dropdown.
    Tries current base URL; on 404 tries alt base (with or without /api) for Nessus Pro.
    Each item has: name, uuid (for create scan), type ('template'|'policy'), id.
    """
    alt_base = _alt_base()
    templates: List[Dict[str, Any]] = []
    policies: List[Dict[str, Any]] = []

    def try_templates(b: Optional[str]) -> None:
        nonlocal templates
        r = _request("GET", "/editor/scan/templates", base_override=b)
        data = r.json()
        raw = data.get("templates") if isinstance(data, dict) else data
        if isinstance(raw, list):
            templates = raw

    try:
        try_templates(None)
    except TenableAPIError as e:
        if e.status_code == 404 and alt_base:
            try:
                try_templates(alt_base)
            except TenableAPIError:
                pass
        else:
            raise

    def try_policies(b: Optional[str]) -> None:
        nonlocal policies
        r = _request("GET", "/policies", base_override=b)
        data = r.json()
        raw = data.get("policies") if isinstance(data, dict) else data
        if isinstance(raw, list):
            policies = raw

    try:
        try_policies(None)
    except TenableAPIError as e:
        if e.status_code == 404 and alt_base:
            try:
                try_policies(alt_base)
            except TenableAPIError:
                pass
        else:
            raise

    items: List[Dict[str, Any]] = []
    for t in templates:
        name = t.get("name") or t.get("title") or str(t.get("uuid", ""))
        uuid_val = t.get("uuid") or t.get("template_uuid")
        if uuid_val:
            items.append({"type": "template", "name": name, "uuid": uuid_val, "id": t.get("id")})

    for p in policies:
        name = p.get("name") or p.get("title") or str(p.get("id", ""))
        pid = p.get("id")
        uuid_val = p.get("uuid") or p.get("template_uuid")
        items.append({
            "type": "policy",
            "name": name,
            "uuid": uuid_val,
            "id": pid,
        })

    return {"items": items, "templates": templates, "policies": policies}


def list_scanners() -> Dict[str, Any]:
    """GET /scanners – list scanners (scanner_id may be required for create scan)."""
    r = _request("GET", "/scanners")
    return r.json()


def upload_file(file_content: bytes, filename: str) -> str:
    """POST /file/upload – upload a file. Returns fileuploaded value for use in file_targets."""
    url = _url("/file/upload")
    verify = settings.tenable_verify_ssl
    h = _headers()
    headers = {k: v for k, v in h.items() if k.lower() != "content-type"}
    try:
        resp = requests.post(
            url,
            headers=headers,
            files={"file": (filename, file_content, "text/plain")},
            timeout=30,
            verify=verify,
        )
    except (requests.RequestException, ProtocolError, OSError) as e:
        raise TenableAPIError(str(e)) from e
    if not resp.ok:
        raise TenableAPIError(
            f"File upload failed: {resp.status_code} {resp.reason}",
            status_code=resp.status_code,
            response_text=resp.text,
        )
    data = resp.json()
    uploaded = data.get("fileuploaded") or data.get("filename") or filename
    return uploaded


def create_scan(
    name: str,
    text_targets: str,
    template_uuid: Optional[str] = None,
    policy_id: Optional[int] = None,
    description: Optional[str] = None,
    scanner_id: Optional[int] = None,
) -> Dict[str, Any]:
    """POST /scans – create scan. Body: { uuid, settings: { name, enabled, text_targets } }. Launch via POST /scans/{scan_id}/launch."""
    settings_dict: Dict[str, Any] = {
        "name": name,
        "enabled": True,
        "text_targets": text_targets.strip(),
    }
    if description is not None:
        settings_dict["description"] = description
    if scanner_id is not None:
        settings_dict["scanner_id"] = scanner_id
    if policy_id is not None:
        settings_dict["policy_id"] = policy_id
    body: Dict[str, Any] = {"settings": settings_dict}
    if template_uuid:
        body["uuid"] = template_uuid
    last_err: Optional[Exception] = None
    for attempt in range(CONNECTION_ERROR_RETRIES + 1):
        try:
            r = _request("POST", "/scans", json_body=body, timeout=CREATE_SCAN_TIMEOUT)
            return r.json()
        except TenableAPIError as e:
            err_str = str(e).lower()
            if "incompleteread" in err_str or "connection" in err_str or "broken" in err_str:
                last_err = e
                if attempt < CONNECTION_ERROR_RETRIES:
                    continue
            raise
        except (ProtocolError, OSError, requests.RequestException) as e:
            last_err = e
            if attempt < CONNECTION_ERROR_RETRIES:
                continue
            msg = str(e)
            if "incompleteread" in msg.lower() or "connection" in msg.lower():
                msg = "Nessus closed the connection before responding (IncompleteRead). Try again; targets are now sent via uploaded file."
            raise TenableAPIError(msg) from e
    if last_err:
        raise TenableAPIError(str(last_err)) from last_err
    raise TenableAPIError("Create scan failed after retries")
