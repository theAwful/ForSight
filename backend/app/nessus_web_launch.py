"""Launch a Nessus Pro scan via the web UI (Selenium).

Uses the same approach as Nessus Pro Start Scan scripts: list scans via API,
then use browser automation to log in and click the launch icon in the Nessus UI.
See: https://github.com/freeload101/SCRIPTS (Nessus Pro Start Scan.py)
"""

import time
from typing import Optional

# Selenium is optional; backend works without it (API-only launch or "Open in Nessus").
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException
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


def is_available() -> bool:
    """Return True if Selenium is installed and web launch can be used."""
    return _SELENIUM_AVAILABLE


def _find_scan_row_by_name(driver, scan_name: str):
    """Find the <tr> in the scans datatable by name. Prefer tr[data-name]; else td.scan-visible-name (data-search/text)."""
    name_clean = (scan_name or "").strip()
    if not name_clean:
        return None
    name_lower = name_clean.lower()

    # 1) Datatable: tr has data-name (and data-id is the scan id)
    try:
        rows = driver.find_elements(By.CSS_SELECTOR, "tr.scan")
        for row in rows:
            data_name = (row.get_attribute("data-name") or "").strip().lower()
            if data_name == name_lower or name_lower in data_name:
                return row
    except Exception:
        pass

    # 2) Fallback: td.scan-visible-name with data-search or text
    rows = driver.find_elements(By.CSS_SELECTOR, "tr")
    for row in rows:
        try:
            name_tds = row.find_elements(By.CSS_SELECTOR, "td.scan-visible-name")
            for td in name_tds:
                data_search = (td.get_attribute("data-search") or "").strip().lower()
                text = (td.text or "").strip().lower()
                if name_lower in data_search or name_lower in text or data_search == name_lower or text == name_lower:
                    return row
        except Exception:
            continue
    return None


def _get_scan_id_from_row(row) -> Optional[int]:
    """Read data-id from the scan row <tr> (the relevant scan id in the datatable)."""
    try:
        data_id = (row.get_attribute("data-id") or "").strip()
        if data_id and data_id.isdigit():
            return int(data_id)
    except Exception:
        pass
    return None


def get_scan_id_by_name(
    base_url: str,
    username: str,
    password: str,
    scan_name: str,
    verify_ssl: bool = False,
    wait_seconds: int = 15,
) -> Optional[int]:
    """
    Open Nessus My Scans (datatable), find the row by scan name, return the row's data-id (scan id).
    Returns None if row not found or data-id missing.
    """
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed. Install with: pip install selenium")
    if not (scan_name and (scan_name or "").strip()):
        raise NessusWebLaunchError("scan_name is required")
    base_url = base_url.rstrip("/")
    driver = None
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        if not verify_ssl:
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--allow-insecure-localhost")
        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(5)
        driver.get(f"{base_url}/")
        WebDriverWait(driver, wait_seconds).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='text']"))
        )
        username_el = driver.find_element(By.CSS_SELECTOR, "input[type='text']")
        password_el = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        username_el.clear()
        username_el.send_keys(username)
        password_el.clear()
        password_el.send_keys(password)
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        time.sleep(2)
        driver.get(f"{base_url}/#/scans/folders/my-scans")
        time.sleep(5)
        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            return None
        return _get_scan_id_from_row(row)
    except NessusWebLaunchError:
        raise
    except Exception as e:
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
    """
    Find the scan row by name in the datatable (tr data-name or td.scan-visible-name). That row's
    data-id is the scan id. Click the launch button in that same row (Selenium), don't call the API.
    """
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed. Install with: pip install selenium")
    if not (scan_name and (scan_name or "").strip()):
        raise NessusWebLaunchError("scan_name is required (find row by name, then click launch in that row)")

    base_url = base_url.rstrip("/")
    driver = None
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        if not verify_ssl:
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--allow-insecure-localhost")

        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(5)

        # 1) Login via web form
        driver.get(f"{base_url}/")
        WebDriverWait(driver, wait_seconds).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='text']"))
        )
        username_el = driver.find_element(By.CSS_SELECTOR, "input[type='text']")
        password_el = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        username_el.clear()
        username_el.send_keys(username)
        password_el.clear()
        password_el.send_keys(password)
        login_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        login_btn.click()

        # 2) Go to My Scans and wait for SPA to render the table
        driver.get(f"{base_url}/#/scans/folders/my-scans")
        time.sleep(5)

        # Find row by scan name, get data-id from that row, then click <i data-id="15" class="glyphicons launch add-tip" original-title="Launch">
        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            raise NessusWebLaunchError(
                f"Could not find scan row named {scan_name!r} on My Scans page. Use the exact name from Nessus."
            )
        scan_id_from_row = _get_scan_id_from_row(row)
        if scan_id_from_row is None:
            raise NessusWebLaunchError(
                f"Found row for {scan_name!r} but row has no data-id. Cannot find launch icon."
            )
        scan_id_str = str(scan_id_from_row)
        for icon_selector in (
            f"i.glyphicons.launch[data-id='{scan_id_str}']",
            f"i[data-id='{scan_id_str}'][class*='launch']",
            f"i[data-id='{scan_id_str}']",
        ):
            try:
                icon = driver.find_element(By.CSS_SELECTOR, icon_selector)
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", icon)
                time.sleep(0.3)
                try:
                    icon.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", icon)
                out = {"ok": True, "message": "Launch triggered via web UI (Selenium clicked launch for that row)."}
                out["scan_id"] = scan_id_from_row
                return out
            except Exception:
                continue
        raise NessusWebLaunchError(
            f"Found row for {scan_name!r} (data-id={scan_id_from_row}) but could not find <i data-id=\"...\" class=\"glyphicons launch ...\"> to click."
        )
    except NessusWebLaunchError:
        raise
    except Exception as e:
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
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
    """
    Find the scan row by name, then click the trash button in that row. We don't use button id.
    """
    if not _SELENIUM_AVAILABLE:
        raise NessusWebLaunchError("Selenium is not installed. Install with: pip install selenium")
    if not (scan_name and (scan_name or "").strip()):
        raise NessusWebLaunchError("scan_name is required (find row by name, then click trash in that row)")

    base_url = base_url.rstrip("/")
    driver = None
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        if not verify_ssl:
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--allow-insecure-localhost")

        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(5)

        driver.get(f"{base_url}/")
        WebDriverWait(driver, wait_seconds).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='text']"))
        )
        username_el = driver.find_element(By.CSS_SELECTOR, "input[type='text']")
        password_el = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        username_el.clear()
        username_el.send_keys(username)
        password_el.clear()
        password_el.send_keys(password)
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        time.sleep(2)
        driver.get(f"{base_url}/#/scans/folders/my-scans")
        time.sleep(5)

        # Find row by scan name, then click the trash button in that row (we don't use button id).
        row = _find_scan_row_by_name(driver, scan_name)
        if not row:
            raise NessusWebLaunchError(
                f"Could not find scan row named {scan_name!r} on My Scans page. Use the exact name from Nessus."
            )
        try:
            action_cell = row.find_element(By.CSS_SELECTOR, "td.scan-action-2")
            icon = action_cell.find_element(By.CSS_SELECTOR, "i.glyphicons.trash")
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", icon)
            time.sleep(0.3)
            try:
                icon.click()
            except Exception:
                driver.execute_script("arguments[0].click();", icon)
        except Exception as e:
            raise NessusWebLaunchError(
                f"Found row for {scan_name!r} but could not click trash in that row: {e}"
            )

        # Dismiss confirmation dialog (Nessus may use an in-page modal or native confirm)
        time.sleep(1.5)
        try:
            alert = driver.switch_to.alert
            alert.accept()
        except Exception:
            pass
        try:
            for btn_text in ("Yes", "OK", "Delete", "Remove", "Confirm"):
                btns = driver.find_elements(By.XPATH, f"//*[contains(translate(text(),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'), '{btn_text.lower()}')]")
                for b in btns:
                    if b.is_displayed() and b.is_enabled():
                        try:
                            b.click()
                            break
                        except Exception:
                            pass
        except Exception:
            pass

        time.sleep(2)
        return {"ok": True, "message": "Delete scan submitted via web UI. Refresh the scan list."}
    except NessusWebLaunchError:
        raise
    except Exception as e:
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def _login_and_go_to_my_scans(driver, base_url: str, username: str, password: str, wait_seconds: int) -> None:
    """Shared: login via form then navigate to My Scans."""
    driver.get(f"{base_url}/")
    WebDriverWait(driver, wait_seconds).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='text']"))
    )
    username_el = driver.find_element(By.CSS_SELECTOR, "input[type='text']")
    password_el = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
    username_el.clear()
    username_el.send_keys(username)
    password_el.clear()
    password_el.send_keys(password)
    login_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
    login_btn.click()
    time.sleep(2)
    driver.get(f"{base_url}/#/scans/folders/my-scans")
    time.sleep(5)


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
    Create a new scan via Nessus web UI: click New Scan, choose template (e.g. Advanced),
    fill Name and Targets, then save. template_key can be 'advanced' or a substring to match
    the template name in the dropdown (e.g. 'Basic', 'Web App').
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
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        if not verify_ssl:
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--allow-insecure-localhost")

        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(5)

        _login_and_go_to_my_scans(driver, base_url, username, password, wait_seconds)

        # Click New Scan: <a href="#/scans/reports/new" id="new-scan" class="button floatright secondary">
        new_scan = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "#new-scan, a[href='#/scans/reports/new']"))
        )
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", new_scan)
        time.sleep(0.5)
        try:
            new_scan.click()
        except Exception:
            driver.execute_script("arguments[0].click();", new_scan)
        time.sleep(5)

        # Click template: Advanced by default, or find by text match
        template_key_lower = (template_key or "advanced").strip().lower()
        template_clicked = False
        # Try exact Advanced icon: <i class="glyphicons template advanced"></i>
        for sel in [
            "i.glyphicons.template.advanced",
            "i.template.advanced",
            "i[class*='template advanced']",
            "i[class*='advanced']",
        ]:
            try:
                el = WebDriverWait(driver, 6).until(EC.element_to_be_clickable((By.CSS_SELECTOR, sel)))
                if template_key_lower == "advanced" or template_key_lower in (el.get_attribute("class") or "").lower():
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", el)
                    time.sleep(0.3)
                    try:
                        el.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", el)
                    template_clicked = True
                    break
            except TimeoutException:
                continue

        if not template_clicked:
            # Grep all template elements and match by text/label
            try:
                templates = driver.find_elements(By.CSS_SELECTOR, "i[class*='template'], [class*='template'] i")
                for t in templates:
                    parent = t.find_element(By.XPATH, "..")
                    label = (parent.text or "").strip().lower()
                    if template_key_lower in label or template_key_lower in (t.get_attribute("class") or "").lower():
                        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", t)
                        time.sleep(0.3)
                        try:
                            t.click()
                        except Exception:
                            driver.execute_script("arguments[0].click();", t)
                        template_clicked = True
                        break
            except Exception:
                pass

        if not template_clicked:
            raise NessusWebLaunchError(
                f"Could not find template '{template_key}'. Tried Advanced and template list."
            )
        time.sleep(3)

        # Name field: <input data-input-id="name" ...>
        name_el = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[data-input-id='name'], input[data-name='Name']"))
        )
        name_el.clear()
        name_el.send_keys((scan_name or "").strip())

        # Targets field (Nessus often uses a textarea or input for targets)
        targets_el = None
        for sel in [
            "input[data-input-id='targets']",
            "textarea[data-input-id='targets']",
            "input[data-name='Targets']",
            "textarea[data-name='Targets']",
            "input[placeholder*='target']",
            "textarea[placeholder*='target']",
            "#targets",
            "[data-input-id='targets']",
        ]:
            try:
                targets_el = driver.find_element(By.CSS_SELECTOR, sel)
                break
            except Exception:
                continue
        if targets_el:
            targets_el.clear()
            targets_el.send_keys((targets_text or "").strip().replace("\n", "\n"))
        else:
            raise NessusWebLaunchError("Could not find targets field on new scan form.")

        # Save: Nessus uses <span class="button secondary primary-action" data-type="editor-action" data-action="save">Save</span>
        time.sleep(0.5)
        save_clicked = False
        for sel in [
            "span[data-action='save']",
            "[data-type='editor-action'][data-action='save']",
            "[data-action='save']",
            "span.primary-action[data-action='save']",
            "button[type='submit']",
            "input[type='submit']",
            "a.button.primary",
            "button.primary",
        ]:
            try:
                btn = driver.find_element(By.CSS_SELECTOR, sel)
                if btn.is_displayed() and btn.is_enabled():
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", btn)
                    time.sleep(0.2)
                    try:
                        btn.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", btn)
                    save_clicked = True
                    break
            except Exception:
                continue
        if not save_clicked:
            # Try by visible text
            try:
                for btn in driver.find_elements(By.XPATH, "//button[contains(translate(text(),'SAVE','save'),'save')] | //a[contains(translate(text(),'SAVE','save'),'save')]"):
                    if btn.is_displayed():
                        btn.click()
                        save_clicked = True
                        break
            except Exception:
                pass

        time.sleep(3)
        return {"ok": True, "message": "Create scan submitted via web UI. Refresh the scan list to see the new scan."}
    except NessusWebLaunchError:
        raise
    except Exception as e:
        raise NessusWebLaunchError(_sanitize_error(str(e))) from e
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
