"""Launch a Nessus Pro scan via the web UI (Selenium).

Uses browser automation to log in and click the launch icon in the Nessus UI.
All UI synchronization uses WebDriverWait — no time.sleep for SPA rendering.

Set FORSIGHT_SELENIUM_DEBUG=1 to save failure screenshots to /tmp/.
"""

import os
import time
from typing import Optional

# Selenium is optional; backend works without it (API-only launch or "Open in Nessus").
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
    _SELENIUM_AVAILABLE = True
except ImportError:
    _SELENIUM_AVAILABLE = False


class NessusWebLaunchError(Exception):
    """Web automation failed (login, navigation, or launch click)."""
    pass


def _sanitize_error(msg: str) -> str:
    """Replace Chrome/Selenium crash stacktraces with a short message."""
    if not msg or len(msg) < 400:
        return msg or "Web automation failed."
    if "Stacktrace" in msg or "#0 0x" in msg or "<unknown>" in msg:
        return "Browser automation failed (Chrome or driver may have crashed). Try the API or Nessus UI."
    return msg[:400] + "…"


def _maybe_screenshot(driver, label: str) -> str:
    """Save a debug screenshot if FORSIGHT_SELENIUM_DEBUG is set. Returns path or ''."""
    if not driver:
        return ""
    if not os.environ.get("FORSIGHT_SELENIUM_DEBUG"):
        return ""
    try:
        path = f"/tmp/nessus_selenium_{label}_{int(time.time())}.png"
        driver.save_screenshot(path)
        return path
    except Exception:
        return ""


def is_available() -> bool:
    """Return True if Selenium is installed and web launch can be used."""
    return _SELENIUM_AVAILABLE


def _build_chrome_options(verify_ssl: bool) -> "Options":
    opts = Options()
    opts.add_argument("--headless")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1920,1080")
    if not verify_ssl:
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--allow-insecure-localhost")
    return opts


def _find_scan_row_by_name(driver, scan_name: str):
    """
    Find the scan table <tr> by name using four progressive strategies.

    Strategy 1: tr[data-name] attribute (Nessus 8.x / 10.x primary)
    Strategy 2: tr.scan class with data-name attribute (older Nessus)
    Strategy 3: td.scan-visible-name with data-search or text match
    Strategy 4: Broadest fallback — any tbody tr whose first 3 tds contain the name
    """
    name_clean = (scan_name or "").strip()
    if not name_clean:
        return None
    name_lower = name_clean.lower()

    # Strategy 1: tr with data-name attribute
    try:
        rows = driver.find_elements(By.CSS_SELECTOR, "tr[data-name]")
        for row in rows:
            data_name = (row.get_attribute("data-name") or "").strip().lower()
            if data_name == name_lower or name_lower in data_name:
                return row
    except Exception:
        pass

    # Strategy 2: tr.scan with data-name
    try:
        rows = driver.find_elements(By.CSS_SELECTOR, "tr.scan")
        for row in rows:
            data_name = (row.get_attribute("data-name") or "").strip().lower()
            if data_name == name_lower or name_lower in data_name:
                return row
    except Exception:
        pass

    # Strategy 3: td.scan-visible-name text / data-search
    try:
        rows = driver.find_elements(By.CSS_SELECTOR, "tr")
        for row in rows:
            name_tds = row.find_elements(By.CSS_SELECTOR, "td.scan-visible-name")
            for td in name_tds:
                data_search = (td.get_attribute("data-search") or "").strip().lower()
                text = (td.text or "").strip().lower()
                if name_lower in data_search or name_lower in text:
                    return row
    except Exception:
        pass

    # Strategy 4: any tbody row whose first 3 cells contain the name
    try:
        all_rows = driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
        for row in all_rows:
            cells = row.find_elements(By.CSS_SELECTOR, "td")
            for cell in cells[:3]:
                cell_text = (cell.text or "").strip().lower()
                if name_lower == cell_text or name_lower in cell_text:
                    return row
    except Exception:
        pass

    return None


def _get_scan_id_from_row(row) -> Optional[int]:
    """Read data-id from the scan row <tr>."""
    try:
        val = row.get_attribute("data-id")
        if val and val.strip().isdigit():
            return int(val.strip())
    except Exception:
        pass
    # Fallback: look for data-id on child elements
    try:
        child = row.find_element(By.CSS_SELECTOR, "[data-id]")
        val = child.get_attribute("data-id")
        if val and val.strip().isdigit():
            return int(val.strip())
    except Exception:
        pass
    return None


def _login_and_go_to_my_scans(
    driver,
    base_url: str,
    username: str,
    password: str,
    wait_seconds: int,
) -> None:
    """
    Log into Nessus via the web form and navigate to My Scans.

    Uses WebDriverWait exclusively — no time.sleep for SPA synchronization.
    Raises NessusWebLaunchError on login failure or navigation timeout.
    """
    # 1. Load the login page and wait for the form
    driver.get(f"{base_url}/")
    try:
        WebDriverWait(driver, wait_seconds).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='text'], input[type='email']"))
        )
    except TimeoutException:
        raise NessusWebLaunchError(
            f"Nessus login page did not load within {wait_seconds}s. "
            f"Check FORSIGHT_TENABLE_BASE_URL ({base_url}) and that Nessus is running."
        )

    # 2. Fill credentials
    try:
        username_el = driver.find_element(By.CSS_SELECTOR, "input[type='text'], input[type='email']")
        password_el = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        username_el.clear()
        username_el.send_keys(username)
        password_el.clear()
        password_el.send_keys(password)
        login_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        login_btn.click()
    except NoSuchElementException as e:
        raise NessusWebLaunchError(f"Could not find login form elements: {e}")

    # 3. Wait for login to complete (redirect away from login form)
    try:
        WebDriverWait(driver, 15).until(
            lambda d: (
                "#/scans" in d.current_url
                or not d.find_elements(By.CSS_SELECTOR, "input[type='password']")
            )
        )
    except TimeoutException:
        # Check for a visible error message in the DOM
        error_text = ""
        for sel in (".login-error", ".alert-danger", "[class*='error']", "[class*='Error']"):
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            for el in els:
                t = (el.text or "").strip()
                if t:
                    error_text = t
                    break
            if error_text:
                break
        raise NessusWebLaunchError(
            "Login to Nessus failed. "
            + (f"Error shown: {error_text}" if error_text else
               "Credentials may be incorrect, or the session cookie was rejected. "
               "Check FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD.")
        )

    # 4. Navigate to My Scans
    driver.get(f"{base_url}/#/scans/folders/my-scans")

    # 5. Wait for the scan table (or empty state) to be present
    try:
        WebDriverWait(driver, wait_seconds).until(
            EC.any_of(
                EC.presence_of_element_located((By.CSS_SELECTOR, "tr[data-name]")),
                EC.presence_of_element_located((By.CSS_SELECTOR, "tr.scan")),
                EC.presence_of_element_located((By.CSS_SELECTOR, "td.scan-visible-name")),
                EC.presence_of_element_located((By.CSS_SELECTOR, "table tbody tr")),
                EC.presence_of_element_located((By.CSS_SELECTOR, ".scans-empty, .empty-state, [class*='empty']")),
            )
        )
    except TimeoutException:
        raise NessusWebLaunchError(
            f"My Scans page did not render the scan table within {wait_seconds}s. "
            "Nessus may be loading slowly. Try increasing wait time or check Nessus health."
        )


def launch_scan_via_web(
    base_url: str,
    username: str,
    password: str,
    scan_id: Optional[int] = None,
    scan_name: Optional[str] = None,
    verify_ssl: bool = False,
    wait_seconds: int = 20,
) -> dict:
    """
    Find the scan row by name, read data-id from that row, then click the launch icon.
    scan_id parameter is ignored — we always find the row by name for reliability.
    """
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed. Install with: pip install selenium")
    if not (scan_name and scan_name.strip()):
        raise NessusWebLaunchError("scan_name is required (find row by name, then click launch in that row)")

    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = webdriver.Chrome(options=_build_chrome_options(verify_ssl))
        driver.implicitly_wait(3)

        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds)

        # Find the scan row by name
        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            shot = _maybe_screenshot(driver, "launch_row_not_found")
            msg = f"Could not find scan row named {scan_name!r} on My Scans page. Use the exact name from Nessus."
            if shot:
                msg += f" [Debug screenshot: {shot}]"
            raise NessusWebLaunchError(msg)

        scan_id_from_row = _get_scan_id_from_row(row)
        if scan_id_from_row is None:
            raise NessusWebLaunchError(
                f"Found row for {scan_name!r} but the row has no data-id. Cannot locate the launch button."
            )

        scan_id_str = str(scan_id_from_row)

        # Try multiple selectors for the launch icon
        icon_selectors = [
            f"i.glyphicons.launch[data-id='{scan_id_str}']",
            f"i[data-id='{scan_id_str}'][class*='launch']",
            f"i[data-id='{scan_id_str}']",
            f"button[data-id='{scan_id_str}'][class*='launch']",
            f"[data-id='{scan_id_str}'] .launch",
            f"[data-id='{scan_id_str}']",
        ]

        for selector in icon_selectors:
            try:
                icon = driver.find_element(By.CSS_SELECTOR, selector)
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", icon)
                try:
                    icon.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", icon)
                return {
                    "ok": True,
                    "scan_id": scan_id_from_row,
                    "message": "Launch triggered via web UI (Selenium clicked launch for that row).",
                }
            except NoSuchElementException:
                continue
            except Exception:
                continue

        # All selectors failed — try clicking within the row itself
        try:
            launch_in_row = row.find_element(By.CSS_SELECTOR, "[class*='launch'], [title*='Launch'], [aria-label*='Launch']")
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", launch_in_row)
            try:
                launch_in_row.click()
            except Exception:
                driver.execute_script("arguments[0].click();", launch_in_row)
            return {
                "ok": True,
                "scan_id": scan_id_from_row,
                "message": "Launch triggered via web UI (fallback row element click).",
            }
        except Exception:
            pass

        shot = _maybe_screenshot(driver, "launch_icon_not_found")
        msg = (
            f"Found row for {scan_name!r} (data-id={scan_id_from_row}) but could not find "
            f"the launch icon to click. Nessus UI may have changed."
        )
        if shot:
            msg += f" [Debug screenshot: {shot}]"
        raise NessusWebLaunchError(msg)

    except NessusWebLaunchError:
        raise
    except Exception as e:
        shot = _maybe_screenshot(driver, "launch_exception")
        msg = _sanitize_error(str(e))
        if shot:
            msg += f" [Debug screenshot: {shot}]"
        raise NessusWebLaunchError(msg) from e
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
    wait_seconds: int = 20,
) -> dict:
    """Find the scan row by name and click the trash icon in that row."""
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed. Install with: pip install selenium")
    if not (scan_name and scan_name.strip()):
        raise NessusWebLaunchError("scan_name is required (find row by name, then click trash in that row)")

    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = webdriver.Chrome(options=_build_chrome_options(verify_ssl))
        driver.implicitly_wait(3)

        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds)

        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            shot = _maybe_screenshot(driver, "delete_row_not_found")
            msg = f"Could not find scan row named {scan_name!r} on My Scans page."
            if shot:
                msg += f" [Debug screenshot: {shot}]"
            raise NessusWebLaunchError(msg)

        # Find trash icon within the row
        trash_found = False
        for sel in (
            "td.scan-action-2 i.glyphicons.trash",
            "i.glyphicons.trash",
            "i[class*='trash']",
            "[class*='trash']",
            "[title*='Delete'], [aria-label*='Delete'], [title*='Trash']",
        ):
            try:
                icon = row.find_element(By.CSS_SELECTOR, sel)
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", icon)
                try:
                    icon.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", icon)
                trash_found = True
                break
            except NoSuchElementException:
                continue

        if not trash_found:
            shot = _maybe_screenshot(driver, "delete_trash_not_found")
            msg = f"Found row for {scan_name!r} but could not click the trash icon."
            if shot:
                msg += f" [Debug screenshot: {shot}]"
            raise NessusWebLaunchError(msg)

        # Dismiss any confirmation dialog — try native alert first, then in-page modal
        # Wait briefly for a dialog to appear
        try:
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            driver.switch_to.alert.accept()
        except TimeoutException:
            pass
        except Exception:
            pass

        # In-page confirmation buttons
        for btn_text in ("Yes", "OK", "Delete", "Remove", "Confirm"):
            try:
                btns = driver.find_elements(
                    By.XPATH,
                    f"//*[contains(translate(normalize-space(text()),'abcdefghijklmnopqrstuvwxyz','abcdefghijklmnopqrstuvwxyz'), '{btn_text.lower()}')]"
                )
                for b in btns:
                    if b.is_displayed() and b.is_enabled():
                        try:
                            b.click()
                            break
                        except Exception:
                            pass
            except Exception:
                pass

        # Wait for the row to disappear (confirmation the delete worked)
        try:
            WebDriverWait(driver, 8).until(
                lambda d: _find_scan_row_by_name(d, scan_name) is None
            )
        except TimeoutException:
            pass  # Row may still be visible briefly; not a hard failure

        return {"ok": True, "message": "Delete scan submitted via web UI. Refresh the scan list."}

    except NessusWebLaunchError:
        raise
    except Exception as e:
        shot = _maybe_screenshot(driver, "delete_exception")
        msg = _sanitize_error(str(e))
        if shot:
            msg += f" [Debug screenshot: {shot}]"
        raise NessusWebLaunchError(msg) from e
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
    """
    Create a new scan via Nessus web UI.
    Clicks New Scan, selects template, fills Name and Targets, then saves.
    template_key: 'advanced' or a substring matching the template name.
    """
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed. Install with: pip install selenium")
    if not (scan_name or "").strip():
        raise NessusWebLaunchError("Scan name is required")
    if not (targets_text or "").strip():
        raise NessusWebLaunchError("At least one target is required")

    base_url = base_url.rstrip("/")
    driver = None
    try:
        driver = webdriver.Chrome(options=_build_chrome_options(verify_ssl))
        driver.implicitly_wait(3)

        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds)

        # Click New Scan button
        try:
            new_scan = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "#new-scan, a[href='#/scans/reports/new']"))
            )
        except TimeoutException:
            # Broader fallback
            try:
                new_scan = WebDriverWait(driver, 5).until(
                    EC.element_to_be_clickable((By.XPATH, "//*[contains(text(),'New Scan') or contains(@href,'new')]"))
                )
            except TimeoutException:
                shot = _maybe_screenshot(driver, "create_no_new_scan_btn")
                msg = "Could not find the 'New Scan' button on My Scans page."
                if shot:
                    msg += f" [Debug screenshot: {shot}]"
                raise NessusWebLaunchError(msg)

        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", new_scan)
        try:
            new_scan.click()
        except Exception:
            driver.execute_script("arguments[0].click();", new_scan)

        # Wait for template selection page
        try:
            WebDriverWait(driver, wait_seconds).until(
                EC.any_of(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "i.glyphicons.template")),
                    EC.presence_of_element_located((By.CSS_SELECTOR, "i[class*='template']")),
                    EC.presence_of_element_located((By.CSS_SELECTOR, ".scan-template-grid")),
                    EC.presence_of_element_located((By.CSS_SELECTOR, "[class*='template']")),
                )
            )
        except TimeoutException:
            shot = _maybe_screenshot(driver, "create_no_template_grid")
            msg = "Template selection page did not load."
            if shot:
                msg += f" [Debug screenshot: {shot}]"
            raise NessusWebLaunchError(msg)

        # Select template
        template_key_lower = (template_key or "advanced").strip().lower()
        template_clicked = False

        # Try exact glyphicon selectors for common templates
        for sel in (
            f"i.glyphicons.template.{template_key_lower}",
            f"i.template.{template_key_lower}",
            "i.glyphicons.template.advanced",
            "i.template.advanced",
        ):
            try:
                el = WebDriverWait(driver, 4).until(EC.element_to_be_clickable((By.CSS_SELECTOR, sel)))
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", el)
                try:
                    el.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", el)
                template_clicked = True
                break
            except (TimeoutException, NoSuchElementException):
                continue

        if not template_clicked:
            # Text-based template matching
            try:
                templates = driver.find_elements(By.CSS_SELECTOR, "i[class*='template'], [class*='template'] a")
                for t in templates:
                    parent = t.find_element(By.XPATH, "..")
                    label = (parent.text or "").strip().lower()
                    cls = (t.get_attribute("class") or "").lower()
                    if template_key_lower in label or template_key_lower in cls:
                        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", t)
                        try:
                            t.click()
                        except Exception:
                            driver.execute_script("arguments[0].click();", t)
                        template_clicked = True
                        break
            except Exception:
                pass

        if not template_clicked:
            shot = _maybe_screenshot(driver, "create_template_not_found")
            msg = f"Could not find template '{template_key}'. Try 'advanced' or check available templates in Nessus."
            if shot:
                msg += f" [Debug screenshot: {shot}]"
            raise NessusWebLaunchError(msg)

        # Wait for the scan settings form (Name and Targets fields)
        try:
            WebDriverWait(driver, wait_seconds).until(
                EC.any_of(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='name'], input[placeholder*='Name'], input[placeholder*='name']")),
                    EC.presence_of_element_located((By.CSS_SELECTOR, "#scan-name")),
                )
            )
        except TimeoutException:
            shot = _maybe_screenshot(driver, "create_form_not_loaded")
            msg = "Scan settings form did not load after template selection."
            if shot:
                msg += f" [Debug screenshot: {shot}]"
            raise NessusWebLaunchError(msg)

        # Fill Name field
        name_selectors = (
            "input[name='name']",
            "#scan-name",
            "input[placeholder*='Name']",
            "input[placeholder*='name']",
            "input[type='text']",
        )
        name_filled = False
        for sel in name_selectors:
            try:
                name_el = driver.find_element(By.CSS_SELECTOR, sel)
                name_el.clear()
                name_el.send_keys(scan_name)
                name_filled = True
                break
            except NoSuchElementException:
                continue

        if not name_filled:
            raise NessusWebLaunchError("Could not find the scan Name input field.")

        # Fill Targets field
        targets_selectors = (
            "textarea[name='text_targets']",
            "textarea[placeholder*='arget']",
            "input[name='text_targets']",
            "#scan-targets",
            "textarea",
        )
        targets_filled = False
        for sel in targets_selectors:
            try:
                targets_el = driver.find_element(By.CSS_SELECTOR, sel)
                targets_el.clear()
                targets_el.send_keys(targets_text)
                targets_filled = True
                break
            except NoSuchElementException:
                continue

        if not targets_filled:
            raise NessusWebLaunchError("Could not find the Targets input field.")

        # Click Save
        save_selectors = (
            "button.button-save",
            "button[type='submit']",
            "[class*='save']",
            "button:contains('Save')",
        )
        saved = False
        for sel in save_selectors:
            try:
                save_btn = driver.find_element(By.CSS_SELECTOR, sel)
                if save_btn.is_displayed() and save_btn.is_enabled():
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", save_btn)
                    try:
                        save_btn.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", save_btn)
                    saved = True
                    break
            except NoSuchElementException:
                continue

        if not saved:
            # XPath fallback for text-matching
            try:
                btns = driver.find_elements(By.XPATH, "//button[contains(text(),'Save') or contains(text(),'save')]")
                for b in btns:
                    if b.is_displayed() and b.is_enabled():
                        b.click()
                        saved = True
                        break
            except Exception:
                pass

        if not saved:
            shot = _maybe_screenshot(driver, "create_no_save_btn")
            msg = "Could not find the Save button on the scan settings form."
            if shot:
                msg += f" [Debug screenshot: {shot}]"
            raise NessusWebLaunchError(msg)

        # Wait for redirect back to My Scans (indicates save succeeded)
        try:
            WebDriverWait(driver, wait_seconds).until(
                lambda d: "my-scans" in d.current_url or "#/scans" in d.current_url
            )
        except TimeoutException:
            pass  # May redirect to scan detail — not a failure

        return {
            "ok": True,
            "message": f"Scan '{scan_name}' created via web UI. Refresh the scan list.",
        }

    except NessusWebLaunchError:
        raise
    except Exception as e:
        shot = _maybe_screenshot(driver, "create_exception")
        msg = _sanitize_error(str(e))
        if shot:
            msg += f" [Debug screenshot: {shot}]"
        raise NessusWebLaunchError(msg) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
