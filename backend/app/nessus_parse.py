"""Parse Nessus .nessus (XML) export into structured hosts and vulnerabilities."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _text(el: Any) -> str:
    if el is None:
        return ""
    return (el.text or "").strip()


def _get_child(parent: Any, tag: str) -> Any:
    if parent is None:
        return None
    for c in parent:
        if c.tag.endswith(tag) or c.tag == tag:
            return c
    return None


def _find_all(parent: Any, tag: str) -> list:
    if parent is None:
        return []
    return [c for c in parent if c.tag.endswith(tag) or c.tag == tag]


def parse_nessus_xml(xml_bytes: bytes) -> dict[str, Any]:
    """
    Parse .nessus XML export. Returns:
    {
      "scan_name": str,
      "hosts": [
        {
          "name": str,           # hostname or IP from ReportHost
          "host_ip": str,        # from HostProperties tag name="host-ip"
          "vulns": [
            {
              "plugin_id": str,
              "plugin_name": str,
              "severity": str,
              "port": str,
              "protocol": str,
              "description": str,
              "plugin_output": str,
              "solution": str,
              "risk_factor": str,
              "synopsis": str,
            }
          ]
        }
      ]
    }
    """
    root = ET.fromstring(xml_bytes)
    report = root.find(".//Report") or root.find(".//{*}Report")
    if report is None:
        for r in root:
            if "Report" in (r.tag or ""):
                report = r
                break
    if report is None:
        return {"scan_name": "", "hosts": []}

    scan_name = report.get("name", "")

    def find_report_hosts(elem: Any) -> list:
        out: list[Any] = []
        tag = elem.tag or ""
        if "ReportHost" in tag:
            out.append(elem)
        for c in elem:
            out.extend(find_report_hosts(c))
        return out

    report_hosts = find_report_hosts(report)
    hosts: list[dict[str, Any]] = []

    for rh in report_hosts:
        name = rh.get("name", "")
        host_ip = name
        for hp in _find_all(rh, "HostProperties") or _find_all(rh, "host-properties"):
            for tag in _find_all(hp, "tag"):
                if tag.get("name") == "host-ip":
                    host_ip = _text(tag) or name
                    break

        vulns: list[dict[str, Any]] = []
        for item in _find_all(rh, "ReportItem"):
            plugin_id = item.get("pluginID", "")
            plugin_name = item.get("pluginName", "")
            severity = item.get("severity", "0")
            port = item.get("port", "")
            protocol = item.get("protocol", "")

            desc_el = _get_child(item, "description") or _get_child(item, "Description")
            plugin_output_el = _get_child(item, "plugin_output") or _get_child(item, "plugin_output")
            solution_el = _get_child(item, "solution") or _get_child(item, "Solution")
            risk_el = _get_child(item, "risk_factor") or _get_child(item, "risk_factor")
            synopsis_el = _get_child(item, "synopsis") or _get_child(item, "Synopsis")

            vulns.append({
                "plugin_id": plugin_id,
                "plugin_name": plugin_name or "",
                "severity": severity,
                "port": port,
                "protocol": protocol or "",
                "description": _text(desc_el),
                "plugin_output": _text(plugin_output_el),
                "solution": _text(solution_el),
                "risk_factor": _text(risk_el),
                "synopsis": _text(synopsis_el),
            })

        hosts.append({
            "name": name,
            "host_ip": host_ip,
            "vulns": vulns,
        })

    return {"scan_name": scan_name, "hosts": hosts}
