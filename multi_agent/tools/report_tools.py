"""
Tools for the Assessor Agent.

Parses ScoutSuite's JavaScript-wrapped JSON report files and returns
structured finding data for LLM-based severity re-assessment.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


# ScoutSuite severity level mapping
_LEVEL_LABEL = {
    "danger": "High",
    "warning": "Medium",
    "info": "Informational",
    "good": "Passed",
}

# Levels the assessor should re-evaluate (ignore Passed / Informational)
_ACTIONABLE_LEVELS = {"danger", "warning"}


def parse_scoutsuite_report(report_dir: str) -> dict:
    """Parse a ScoutSuite report directory and return all actionable findings.

    Reads the scoutsuite_results*.js file, strips the JavaScript wrapper,
    and extracts all findings with level 'danger' (High) or 'warning' (Medium).

    Args:
        report_dir: Path to a ScoutSuite report directory created by the scanner.

    Returns:
        dict with keys:
            status          - "success" | "failure"
            account_id      - Cloud account/project identifier
            provider        - Cloud provider (aws / azure / gcp)
            scan_time       - When the scan was run
            total_findings  - Total actionable findings found
            findings        - List of finding dicts, each with:
                               service, finding_id, title, description,
                               original_level, original_severity_label,
                               flagged_items, checked_items,
                               affected_resources (up to 20 items),
                               compliance, references
            message         - Error message if status is failure
    """
    report_path = Path(report_dir)
    if not report_path.exists():
        return {"status": "failure", "findings": [], "message": f"Directory not found: {report_dir}"}

    results_file = _find_results_file(report_path)
    if results_file is None:
        return {
            "status": "failure",
            "findings": [],
            "message": f"No scoutsuite_results*.js file found under {report_dir}",
        }

    try:
        data = _load_results_js(results_file)
    except Exception as exc:
        return {"status": "failure", "findings": [], "message": f"Failed to parse results: {exc}"}

    account_id = data.get("account_id", data.get("project_id", "unknown"))
    provider = data.get("provider_code", "unknown")
    scan_time = _extract_scan_time(data)
    findings = _extract_findings(data)

    return {
        "status": "success",
        "account_id": account_id,
        "provider": provider,
        "scan_time": scan_time,
        "total_findings": len(findings),
        "findings": findings,
        "message": f"Extracted {len(findings)} actionable finding(s) from {account_id}.",
    }


def get_findings_summary(report_dir: str) -> dict:
    """Return a lightweight count-only summary of findings by severity level.

    Useful for a quick overview before full parsing.

    Args:
        report_dir: Path to a ScoutSuite report directory.

    Returns:
        dict with keys:
            status   - "success" | "failure"
            summary  - dict mapping severity label to count (e.g. {"High": 3, "Medium": 7})
            message  - summary sentence
    """
    result = parse_scoutsuite_report(report_dir)
    if result["status"] != "success":
        return result

    counts: dict[str, int] = {}
    for f in result["findings"]:
        label = f["original_severity_label"]
        counts[label] = counts.get(label, 0) + 1

    total = sum(counts.values())
    return {
        "status": "success",
        "account_id": result["account_id"],
        "summary": counts,
        "message": f"{total} actionable finding(s): {counts}",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_results_file(directory: Path) -> Path | None:
    candidates = sorted(directory.rglob("scoutsuite_results*.js"))
    return candidates[0] if candidates else None


def _load_results_js(path: Path) -> dict[str, Any]:
    """Strip the `scoutsuite_results = ` JavaScript prefix and parse JSON."""
    raw = path.read_text(encoding="utf-8")
    # Remove leading JS variable assignment (handles variations with/without spaces/newlines)
    cleaned = re.sub(r"^\s*scoutsuite_results\s*=\s*", "", raw, flags=re.MULTILINE)
    # Remove trailing semicolons
    cleaned = cleaned.rstrip().rstrip(";")
    return json.loads(cleaned)


def _extract_scan_time(data: dict) -> str:
    try:
        return data["last_run"]["time"]
    except (KeyError, TypeError):
        return "unknown"


def _extract_findings(data: dict) -> list[dict]:
    """Walk the services tree and collect all danger/warning findings."""
    findings: list[dict] = []

    services: dict = data.get("services", {})

    for service_name, service_data in services.items():
        if not isinstance(service_data, dict):
            continue

        # Findings may live under service_data["findings"] or service_data["checks"]
        raw_findings: dict = service_data.get("findings") or service_data.get("checks") or {}

        for finding_id, finding in raw_findings.items():
            if not isinstance(finding, dict):
                continue

            level = finding.get("level", "")
            if level not in _ACTIONABLE_LEVELS:
                continue

            flagged = finding.get("flagged_items", 0) or 0
            checked = finding.get("checked_items", 0) or 0

            # Collect affected resource identifiers (cap at 20 to keep context manageable)
            items: list[str] = finding.get("items", []) or []
            affected = [str(i) for i in items[:20]]

            findings.append({
                "service": service_name,
                "finding_id": finding_id,
                "title": finding.get("description", finding_id),
                "description": finding.get("rationale", finding.get("description", "")),
                "original_level": level,
                "original_severity_label": _LEVEL_LABEL.get(level, level.capitalize()),
                "flagged_items": flagged,
                "checked_items": checked,
                "affected_resources": affected,
                "compliance": finding.get("compliance", {}),
                "references": finding.get("references", []),
            })

    # Sort: danger first, then by flagged item count descending
    findings.sort(
        key=lambda f: (0 if f["original_level"] == "danger" else 1, -f["flagged_items"])
    )
    return findings
