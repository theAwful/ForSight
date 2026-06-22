"""Launch a Nessus Pro scan via the web UI (Selenium).

Uses the same approach as Nessus Pro Start Scan scripts: list scans via API,
then use browser automation to log in and click the launch icon in the Nessus UI.

DEBUG MODE:
  Set FORSIGHT_SELENIUM_DEBUG=1 in backend/.env to enable verbose tracing
  and screenshot/HTML capture at each step. Files are saved to:
    backend/data/selenium_debug/<timestamp>_<step>.png/.html
"""

import os
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

# Selenium is optional; backend works without it (API-only launch or "Open in Nessus").
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
    _SELENIUM_AVAILABLE = True
except ImportError:
    _SELENIUM_AVAILABLE = False

logger = logging.getLogger("forsight.selenium")

_tpl_cache: dict = {"data": [], "ts": 0.0}
_TPL_TTL = 600  # 10 minutes

# ── Debug helpers ─────────────────────────────────────────────────────────────

def _debug_enabled() -> bool:
    val = os.environ.get("FORSIGHT_SELENIUM_DEBUG", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _debug_dir() -> Path:
    # backend/app/nessus_web_launch.py -> backend/data/selenium_debug/
    here = Path(__file__).resolve().parent.parent
    d = here / "data" / "selenium_debug"
    d.mkdir(parents=True, exist_ok=True)
    return d


_RUN_TS = None  # Set per-run

def _new_run_ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _snap(driver, step: str, run_ts: str) -> None:
    """Save a screenshot + HTML snapshot of the current page if debug is on."""
    if not _debug_enabled() or driver is None:
        return
    try:
        d = _debug_dir()
        safe_step = "".join(c if c.isalnum() or c in "-_" else "_" for c in step)
        png_path  = d / f"{run_ts}_{safe_step}.png"
        html_path = d / f"{run_ts}_{safe_step}.html"
        try:
            driver.save_screenshot(str(png_path))
        except Exception as e:
            logger.warning(f"Failed to save screenshot at {step}: {e}")
        try:
            html = driver.page_source or ""
            html_path.write_text(html, encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Failed to save HTML at {step}: {e}")
        logger.info(f"[selenium-debug] {step} -> {png_path.name}")
    except Exception as e:
        logger.warning(f"_snap failed: {e}")


def _log(step: str) -> None:
    if _debug_enabled():
        logger.info(f"[selenium] {step}")


# ── Errors / availability ─────────────────────────────────────────────────────

class NessusWebLaunchError(Exception):
    """Web automation failed (login, navigation, or launch click)."""
    pass


def _sanitize_error(msg: str) -> str:
    if not msg or len(msg) < 400:
        return msg or "Web automation failed."
    if "Stacktrace" in msg or "#0 0x" in msg or "<unknown>" in msg:
        return "Browser automation failed (Chrome or driver may have crashed). Try the API or Nessus UI."
    return msg[:400] + "…"


def is_available() -> bool:
    return _SELENIUM_AVAILABLE


# ── Driver ────────────────────────────────────────────────────────────────────

def _build_driver(verify_ssl: bool):
    chrome_options = Options()
    # Force visible mode in debug so you can watch what's happening
    if not _debug_enabled():
        chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    if not verify_ssl:
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--allow-insecure-localhost")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    driver = webdriver.Chrome(options=chrome_options)
    driver.implicitly_wait(3)
    return driver


# ── Row finders ───────────────────────────────────────────────────────────────

def _find_scan_row_by_name(driver, scan_name: str):
    """Find the <tr class='scan'> by data-name. Falls back to td.scan-visible-name."""
    name_clean = (scan_name or "").strip()
    if not name_clean:
        return None
    name_lower = name_clean.lower()

    # 1) tr.scan with data-name attribute (this is what your DOM shows)
    try:
        rows = driver.find_elements(By.CSS_SELECTOR, "tr.scan")
        for row in rows:
            data_name = (row.get_attribute("data-name") or "").strip().lower()
            if data_name == name_lower or (data_name and name_lower in data_name):
                _log(f"row found by data-name: {data_name!r}")
                return row
    except Exception as e:
        _log(f"data-name search failed: {e}")

    # 2) Fallback: td.scan-visible-name with data-search or text
    try:
        rows = driver.find_elements(By.CSS_SELECTOR, "tr")
        for row in rows:
            try:
                name_tds = row.find_elements(By.CSS_SELECTOR, "td.scan-visible-name")
                for td in name_tds:
                    data_search = (td.get_attribute("data-search") or "").strip().lower()
                    text = (td.text or "").strip().lower()
                    if (
                        name_lower in data_search
                        or name_lower in text
                        or data_search == name_lower
                        or text == name_lower
                    ):
                        _log(f"row found by td.scan-visible-name: {data_search or text!r}")
                        return row
            except Exception:
                continue
    except Exception as e:
        _log(f"td search failed: {e}")
    return None


def _get_scan_id_from_row(row) -> Optional[int]:
    try:
        data_id = (row.get_attribute("data-id") or "").strip()
        if data_id and data_id.isdigit():
            return int(data_id)
    except Exception:
        pass
    return None


# ── Login flow ────────────────────────────────────────────────────────────────

def _login_and_go_to_my_scans(driver, base_url: str, username: str, password: str, wait_seconds: int, run_ts: str) -> None:
    """Login via form then navigate to My Scans. Waits for the scans datatable to render."""
    _log(f"navigating to {base_url}/")
    driver.get(f"{base_url}/")
    _snap(driver, "01_landing_page", run_ts)

    # Wait for login form. Nessus uses different login form elements depending on version.
    # Try several known selectors.
    login_input_selectors = [
        "input[name='username']",
        "input#username",
        "input[type='text'][autocomplete='username']",
        "input[type='text']",  # fallback
    ]
    pw_input_selectors = [
        "input[name='password']",
        "input#password",
        "input[type='password']",
    ]

    username_el = None
    for sel in login_input_selectors:
        try:
            username_el = WebDriverWait(driver, wait_seconds).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, sel))
            )
            if username_el.is_displayed():
                _log(f"login username field found via: {sel}")
                break
        except TimeoutException:
            continue
    if not username_el:
        _snap(driver, "02_login_username_not_found", run_ts)
        raise NessusWebLaunchError(
            "Could not find Nessus username input. Verify FORSIGHT_TENABLE_BASE_URL is correct "
            "and the Nessus login page is reachable."
        )

    password_el = None
    for sel in pw_input_selectors:
        try:
            password_el = driver.find_element(By.CSS_SELECTOR, sel)
            if password_el.is_displayed():
                break
        except NoSuchElementException:
            continue
    if not password_el:
        _snap(driver, "02_login_password_not_found", run_ts)
        raise NessusWebLaunchError("Could not find Nessus password input on the login page.")

    _snap(driver, "02_login_form_visible", run_ts)
    username_el.clear()
    username_el.send_keys(username)
    password_el.clear()
    password_el.send_keys(password)
    _log("submitted login credentials")

    # Try multiple submit button strategies
    submitted = False
    for sel in ("button[type='submit']", "input[type='submit']", "button.button-primary", "button.primary"):
        try:
            btn = driver.find_element(By.CSS_SELECTOR, sel)
            if btn.is_displayed():
                btn.click()
                submitted = True
                _log(f"clicked submit via {sel}")
                break
        except NoSuchElementException:
            continue
    if not submitted:
        # Fall back to pressing Enter in the password field
        password_el.send_keys(Keys.ENTER)
        _log("submitted login via Enter key")

    # Wait for login to finish — either we land in the SPA or we get an error
    time.sleep(2)
    _snap(driver, "03_after_login_submit", run_ts)

    # Detect login failure: if we still see a password input, login probably failed
    try:
        still_pw = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
        visible_pw = [e for e in still_pw if e.is_displayed()]
        if visible_pw:
            _snap(driver, "03b_login_likely_failed", run_ts)
            raise NessusWebLaunchError(
                "Login appears to have failed (password field still visible). "
                "Verify FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD."
            )
    except NessusWebLaunchError:
        raise
    except Exception:
        pass

    # Navigate to My Scans
    target_url = f"{base_url}/#/scans/folders/my-scans"
    _log(f"navigating to {target_url}")
    driver.get(target_url)

    # Wait up to 20s for the datatable to render
    try:
        WebDriverWait(driver, 20).until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, "table.scans, tr.scan, td.scan-visible-name, span.empty-results")) > 0
        )
        _log("My Scans page rendered")
    except TimeoutException:
        _snap(driver, "04_my_scans_timeout", run_ts)
        raise NessusWebLaunchError(
            "My Scans page did not render within 20s. Nessus may be slow or unreachable."
        )

    _snap(driver, "04_my_scans_loaded", run_ts)


# ── Public entrypoints ────────────────────────────────────────────────────────

def get_scan_id_by_name(
    base_url: str,
    username: str,
    password: str,
    scan_name: str,
    verify_ssl: bool = False,
    wait_seconds: int = 15,
) -> Optional[int]:
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed.")
    if not (scan_name or "").strip():
        raise NessusWebLaunchError("scan_name is required")

    run_ts = _new_run_ts()
    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = _build_driver(verify_ssl)
        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds, run_ts)
        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            _snap(driver, "05_row_not_found", run_ts)
            return None
        return _get_scan_id_from_row(row)
    except NessusWebLaunchError:
        raise
    except Exception as e:
        if driver:
            _snap(driver, "99_unexpected_error", run_ts)
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def launch_scan_via_web(
    base_url: str,
    username: str,
    password: str,
    scan_id: Optional[int] = None,
    scan_name: Optional[str] = None,
    verify_ssl: bool = False,
    wait_seconds: int = 15,
) -> dict:
    """Find row by name, then click the launch icon for that row's data-id."""
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed.")
    if not (scan_name or "").strip():
        raise NessusWebLaunchError("scan_name is required")

    run_ts = _new_run_ts()
    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = _build_driver(verify_ssl)
        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds, run_ts)

        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            _snap(driver, "05_row_not_found", run_ts)
            raise NessusWebLaunchError(
                f"Could not find scan row named {scan_name!r}. Verify the name matches Nessus exactly."
            )

        scan_id_from_row = _get_scan_id_from_row(row)
        if scan_id_from_row is None:
            _snap(driver, "05b_no_data_id", run_ts)
            raise NessusWebLaunchError(
                f"Found row for {scan_name!r} but data-id attribute is missing or empty."
            )

        _snap(driver, "05_row_found", run_ts)
        scan_id_str = str(scan_id_from_row)

        # Find launch icon — your DOM: <i data-id="5" class="glyphicons launch add-tip">
        for icon_selector in (
            f"i.glyphicons.launch[data-id='{scan_id_str}']",
            f"i[data-id='{scan_id_str}'][class*='launch']",
            f"tr[data-id='{scan_id_str}'] i.glyphicons.launch",
            f"tr[data-id='{scan_id_str}'] td.scan-action-1 i",
            f"i[data-id='{scan_id_str}']",
        ):
            try:
                icon = driver.find_element(By.CSS_SELECTOR, icon_selector)
                _log(f"launch icon found via: {icon_selector}")
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", icon)
                time.sleep(0.3)
                _snap(driver, "06_before_launch_click", run_ts)
                try:
                    icon.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", icon)
                time.sleep(1.5)
                _snap(driver, "07_after_launch_click", run_ts)
                return {
                    "ok": True,
                    "message": "Launch triggered via web UI.",
                    "scan_id": scan_id_from_row,
                }
            except NoSuchElementException:
                continue

        _snap(driver, "06_launch_icon_not_found", run_ts)
        raise NessusWebLaunchError(
            f"Found row for {scan_name!r} (data-id={scan_id_from_row}) but no launch icon. "
            f"Inspect screenshots in backend/data/selenium_debug/."
        )
    except NessusWebLaunchError:
        raise
    except Exception as e:
        if driver:
            _snap(driver, "99_unexpected_error", run_ts)
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def pause_scan_via_web(
    base_url: str,
    username: str,
    password: str,
    scan_name: str,
    verify_ssl: bool = False,
    wait_seconds: int = 15,
) -> dict:
    """Pause a running scan via the My Scans pause icon.
    
    DOM: <i data-id="N" class="glyphicons pause add-tip" original-title="Pause">
    """
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed.")
    if not (scan_name or "").strip():
        raise NessusWebLaunchError("scan_name is required")

    run_ts = _new_run_ts()
    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = _build_driver(verify_ssl)
        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds, run_ts)

        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            _snap(driver, "05_row_not_found", run_ts)
            raise NessusWebLaunchError(f"Could not find scan row named {scan_name!r}.")

        scan_id_from_row = _get_scan_id_from_row(row)
        if scan_id_from_row is None:
            raise NessusWebLaunchError(f"Row for {scan_name!r} has no data-id.")

        scan_id_str = str(scan_id_from_row)
        # Try multiple selectors — Nessus uses i.glyphicons.pause for the pause icon
        for sel in (
            f"i.glyphicons.pause[data-id='{scan_id_str}']",
            f"i[data-id='{scan_id_str}'][class*='pause']",
            f"tr[data-id='{scan_id_str}'] i.glyphicons.pause",
        ):
            try:
                icon = driver.find_element(By.CSS_SELECTOR, sel)
                _log(f"pause icon found via: {sel}")
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", icon)
                time.sleep(0.3)
                _snap(driver, "06_before_pause_click", run_ts)
                try:
                    icon.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", icon)
                time.sleep(1.5)
                _snap(driver, "07_after_pause_click", run_ts)
                return {"ok": True, "message": "Pause triggered via web UI.", "scan_id": scan_id_from_row}
            except NoSuchElementException:
                continue

        _snap(driver, "06_pause_icon_not_found", run_ts)
        raise NessusWebLaunchError(
            f"Found row for {scan_name!r} but no pause icon (scan may not be running)."
        )
    except NessusWebLaunchError:
        raise
    except Exception as e:
        if driver:
            _snap(driver, "99_unexpected_error", run_ts)
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def stop_scan_via_web(
    base_url: str,
    username: str,
    password: str,
    scan_name: str,
    verify_ssl: bool = False,
    wait_seconds: int = 15,
) -> dict:
    """Stop a running or paused scan via the My Scans stop icon.

    DOM: <i data-id="N" class="glyphicons stop add-tip" original-title="Stop">
    """
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed.")
    if not (scan_name or "").strip():
        raise NessusWebLaunchError("scan_name is required")

    run_ts = _new_run_ts()
    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = _build_driver(verify_ssl)
        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds, run_ts)

        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            _snap(driver, "05_row_not_found", run_ts)
            raise NessusWebLaunchError(f"Could not find scan row named {scan_name!r}.")

        scan_id_from_row = _get_scan_id_from_row(row)
        if scan_id_from_row is None:
            raise NessusWebLaunchError(f"Row for {scan_name!r} has no data-id.")

        scan_id_str = str(scan_id_from_row)
        for sel in (
            f"i.glyphicons.stop[data-id='{scan_id_str}']",
            f"i[data-id='{scan_id_str}'][class*='stop']",
            f"tr[data-id='{scan_id_str}'] i.glyphicons.stop",
        ):
            try:
                icon = driver.find_element(By.CSS_SELECTOR, sel)
                _log(f"stop icon found via: {sel}")
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", icon)
                time.sleep(0.3)
                _snap(driver, "06_before_stop_click", run_ts)
                try:
                    icon.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", icon)
                # Stop may show a confirmation dialog
                time.sleep(1.5)
                # Try to confirm if dialog appears
                for btn_text in ("Stop", "Confirm", "Yes", "OK"):
                    btns = driver.find_elements(
                        By.XPATH,
                        f"//button[contains(translate(text(),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'{btn_text.lower()}')]",
                    )
                    for b in btns:
                        if b.is_displayed() and b.is_enabled():
                            try:
                                b.click()
                                _log(f"clicked stop confirm: {btn_text}")
                                break
                            except Exception:
                                pass
                time.sleep(1)
                _snap(driver, "07_after_stop_click", run_ts)
                return {"ok": True, "message": "Stop triggered via web UI.", "scan_id": scan_id_from_row}
            except NoSuchElementException:
                continue

        _snap(driver, "06_stop_icon_not_found", run_ts)
        raise NessusWebLaunchError(
            f"Found row for {scan_name!r} but no stop icon (scan may not be running)."
        )
    except NessusWebLaunchError:
        raise
    except Exception as e:
        if driver:
            _snap(driver, "99_unexpected_error", run_ts)
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def list_templates_via_web(
    base_url: str,
    username: str,
    password: str,
    verify_ssl: bool = False,
    wait_seconds: int = 15,
) -> list:
    """Open New Scan, list available template titles, return list of {title, category}.
    Results are cached for _TPL_TTL seconds to avoid spinning up Selenium on every call.
    """
    now = time.time()
    if _tpl_cache["data"] and (now - _tpl_cache["ts"]) < _TPL_TTL:
        return _tpl_cache["data"]

    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed.")
    run_ts = _new_run_ts()
    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = _build_driver(verify_ssl)
        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds, run_ts)

        try:
            new_scan = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "#new-scan, a[href='#/scans/reports/new']"))
            )
            try:
                new_scan.click()
            except Exception:
                driver.execute_script("arguments[0].click();", new_scan)
        except TimeoutException:
            raise NessusWebLaunchError("Could not click New Scan to enumerate templates.")

        try:
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "a.library-item"))
            )
        except TimeoutException:
            raise NessusWebLaunchError("Template list did not load.")

        templates = []
        try:
            categories = driver.find_elements(By.CSS_SELECTOR, "div.category-templates")
            for cat in categories:
                category_name = (cat.get_attribute("data-category") or "").strip()
                links = cat.find_elements(By.CSS_SELECTOR, "a.library-item")
                for link in links:
                    try:
                        title_el = link.find_element(By.CSS_SELECTOR, "h5.title")
                        title = (title_el.text or "").strip()
                        if title:
                            templates.append({"title": title, "category": category_name})
                    except NoSuchElementException:
                        continue
        except Exception:
            pass

        _tpl_cache["data"] = templates
        _tpl_cache["ts"] = time.time()
        return templates
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def delete_scan_via_web(
    base_url: str,
    username: str,
    password: str,
    scan_id: Optional[int] = None,
    scan_name: Optional[str] = None,
    verify_ssl: bool = False,
    wait_seconds: int = 15,
) -> dict:
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed.")
    if not (scan_name or "").strip():
        raise NessusWebLaunchError("scan_name is required")

    run_ts = _new_run_ts()
    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = _build_driver(verify_ssl)
        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds, run_ts)

        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            _snap(driver, "05_row_not_found", run_ts)
            raise NessusWebLaunchError(f"Could not find scan row named {scan_name!r}.")

        try:
            action_cell = row.find_element(By.CSS_SELECTOR, "td.scan-action-2")
            icon = action_cell.find_element(By.CSS_SELECTOR, "i.glyphicons.trash")
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", icon)
            time.sleep(0.3)
            _snap(driver, "06_before_delete_click", run_ts)
            try:
                icon.click()
            except Exception:
                driver.execute_script("arguments[0].click();", icon)
        except Exception as e:
            _snap(driver, "06_delete_icon_not_found", run_ts)
            raise NessusWebLaunchError(f"Could not click trash for {scan_name!r}: {e}")

        time.sleep(1.5)
        # Try alert, then any visible "Yes/Confirm/Delete" button
        try:
            alert = driver.switch_to.alert
            alert.accept()
            _log("accepted browser alert")
        except Exception:
            for btn_text in ("Delete", "Confirm", "Yes", "OK", "Remove"):
                btns = driver.find_elements(
                    By.XPATH,
                    f"//button[contains(translate(text(),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'{btn_text.lower()}')]",
                )
                for b in btns:
                    if b.is_displayed() and b.is_enabled():
                        try:
                            b.click()
                            _log(f"clicked confirm '{btn_text}'")
                            break
                        except Exception:
                            pass

        time.sleep(2)
        _snap(driver, "07_after_delete", run_ts)
        return {"ok": True, "message": "Delete submitted via web UI."}
    except NessusWebLaunchError:
        raise
    except Exception as e:
        if driver:
            _snap(driver, "99_unexpected_error", run_ts)
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def create_scan_via_web(
    base_url: str,
    username: str,
    password: str,
    scan_name: str,
    targets_text: str,
    template_key: str = "advanced",
    verify_ssl: bool = False,
    wait_seconds: int = 20,
) -> dict:
    """Create a new scan via Nessus UI: New Scan → template → name + targets → Save."""
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed.")
    if not (scan_name or "").strip():
        raise NessusWebLaunchError("Scan name is required")
    if not (targets_text or "").strip():
        raise NessusWebLaunchError("At least one target is required")

    run_ts = _new_run_ts()
    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = _build_driver(verify_ssl)
        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds, run_ts)

        # Click "New Scan"
        try:
            new_scan = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "#new-scan, a[href='#/scans/reports/new']"))
            )
            _snap(driver, "10_before_new_scan_click", run_ts)
            try:
                new_scan.click()
            except Exception:
                driver.execute_script("arguments[0].click();", new_scan)
            _log("clicked New Scan")
        except TimeoutException:
            _snap(driver, "10_new_scan_btn_not_found", run_ts)
            raise NessusWebLaunchError("Could not find 'New Scan' button on My Scans page.")

        time.sleep(2)
        _snap(driver, "11_template_picker", run_ts)

        # Wait for template picker (a.library-item) to render
        try:
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "a.library-item"))
            )
        except TimeoutException:
            _snap(driver, "11_template_picker_timeout", run_ts)
            raise NessusWebLaunchError(
                "Template picker did not load. Verify Nessus is reachable and login worked."
            )

        # Pick template — DOM: <a class="library-item"><h5 class="title">Basic Network Scan</h5></a>
        # template_key is matched (case-insensitive, substring) against the h5.title text
        tpl_key_lower = (template_key or "advanced").strip().lower()
        tpl_clicked = False

        try:
            template_links = driver.find_elements(By.CSS_SELECTOR, "a.library-item")
            _log(f"found {len(template_links)} template links")
            best_match = None
            best_match_text = ""
            for link in template_links:
                try:
                    title_el = link.find_element(By.CSS_SELECTOR, "h5.title")
                    title_text = (title_el.text or "").strip().lower()
                    _log(f"  template option: {title_text!r}")
                    if not title_text:
                        continue
                    if title_text == tpl_key_lower or tpl_key_lower in title_text:
                        # Prefer exact match, otherwise first substring match
                        if title_text == tpl_key_lower:
                            best_match = link
                            best_match_text = title_text
                            break
                        elif best_match is None:
                            best_match = link
                            best_match_text = title_text
                except NoSuchElementException:
                    continue

            if best_match is not None:
                _log(f"clicking template {best_match_text!r}")
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", best_match)
                time.sleep(0.3)
                try:
                    best_match.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", best_match)
                tpl_clicked = True
        except Exception as e:
            _log(f"template click error: {e}")

        if not tpl_clicked:
            _snap(driver, "11_template_not_found", run_ts)
            available_titles = []
            try:
                for el in driver.find_elements(By.CSS_SELECTOR, "a.library-item h5.title"):
                    t = (el.text or "").strip()
                    if t:
                        available_titles.append(t)
            except Exception:
                pass
            available_str = ", ".join(available_titles[:10]) if available_titles else "(none visible)"
            raise NessusWebLaunchError(
                f"Could not find scan template matching {template_key!r}. "
                f"Available templates: {available_str}"
            )

        time.sleep(3)
        _snap(driver, "12_template_clicked", run_ts)

        # Wait for scan-editor form to load
        # DOM: <input data-input-id="name" data-name="Name" type="text" class="editor-input required">
        try:
            name_field = WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((
                    By.CSS_SELECTOR,
                    "input[data-input-id='name'], input[data-name='Name']"
                ))
            )
            _log("scan editor loaded — name field found")
        except TimeoutException:
            _snap(driver, "13_editor_not_loaded", run_ts)
            raise NessusWebLaunchError(
                "Scan editor did not load after picking template. "
                "Inspect screenshots in backend/data/selenium_debug/."
            )

        # Use JS to clear and set value — Nessus uses a custom editor that doesn't always
        # respond to send_keys after .clear()
        driver.execute_script("arguments[0].focus();", name_field)
        name_field.clear()
        name_field.send_keys(scan_name)
        _log(f"set scan name: {scan_name!r}")

        # Targets textarea — your DOM: <textarea data-input-id="text_targets" data-name="Targets">
        try:
            targets_field = driver.find_element(
                By.CSS_SELECTOR,
                "textarea[data-input-id='text_targets'], textarea[data-name='Targets']"
            )
        except NoSuchElementException:
            _snap(driver, "13_targets_field_not_found", run_ts)
            raise NessusWebLaunchError("Could not find Targets textarea on scan editor page.")

        targets_field.clear()
        targets_field.send_keys(targets_text)
        _snap(driver, "14_form_filled", run_ts)
        _log(f"filled name + {len(targets_text.splitlines())} target lines")

        # Save — your DOM: <span data-action="save">Save</span>
        save_clicked = False
        for sel in (
            "span[data-action='save']",
            "span.button.primary-action",
            "button.button.primary-action",
        ):
            try:
                save_btn = driver.find_element(By.CSS_SELECTOR, sel)
                if save_btn.is_displayed():
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", save_btn)
                    time.sleep(0.3)
                    try:
                        save_btn.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", save_btn)
                    save_clicked = True
                    _log(f"clicked save via {sel}")
                    break
            except NoSuchElementException:
                continue

        if not save_clicked:
            _snap(driver, "15_save_not_found", run_ts)
            raise NessusWebLaunchError("Could not find Save button on scan editor.")

        time.sleep(2)
        _snap(driver, "16_after_save", run_ts)

        return {"ok": True, "message": f"Scan {scan_name!r} created via web UI."}
    except NessusWebLaunchError:
        raise
    except Exception as e:
        if driver:
            _snap(driver, "99_unexpected_error", run_ts)
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
