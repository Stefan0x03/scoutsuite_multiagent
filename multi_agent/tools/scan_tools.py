"""
Tools for the Scanner Agent.

These are plain Python functions that google-adk exposes to the LLM.
All return a dict so the LLM gets structured, readable results.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow imports from the repo root (scout_runner package)
_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scout_runner.config import load_config
from scout_runner.logger import setup_logging
from scout_runner.runner import run_all, run_scan


def run_scoutsuite_scan(
    credentials_file: str,
    reports_dir: str = "reports",
    scan_names: str = "",
) -> dict:
    """Run one or more ScoutSuite scans defined in a YAML credentials file.

    Args:
        credentials_file: Path to the YAML credentials file (e.g. credentials.yaml).
        reports_dir: Root directory where scan reports will be saved (default: reports/).
        scan_names: Comma-separated list of scan names to run.
                    Leave empty to run all scans in the file.

    Returns:
        dict with keys:
            status       - "success" | "partial_failure" | "failure"
            reports_root - Absolute path to the reports root directory
            message      - Human-readable summary
            failed_count - Number of scans that failed
            total_count  - Total number of scans attempted
    """
    setup_logging(debug=False)

    creds_path = Path(credentials_file)
    if not creds_path.exists():
        return {
            "status": "failure",
            "message": f"Credentials file not found: {credentials_file}",
            "reports_root": None,
            "failed_count": 0,
            "total_count": 0,
        }

    try:
        config = load_config(creds_path)
    except Exception as exc:
        return {
            "status": "failure",
            "message": f"Failed to parse credentials file: {exc}",
            "reports_root": None,
            "failed_count": 0,
            "total_count": 0,
        }

    scans = config.scans
    if scan_names:
        wanted = {n.strip() for n in scan_names.split(",") if n.strip()}
        scans = [s for s in scans if s.name in wanted]
        if not scans:
            return {
                "status": "failure",
                "message": f"No scans matched the filter: {scan_names}",
                "reports_root": None,
                "failed_count": 0,
                "total_count": 0,
            }

    reports_root = Path(reports_dir)
    failures = run_all(scans, reports_root)
    total = len(scans)
    passed = total - failures

    status = "success" if failures == 0 else ("partial_failure" if passed > 0 else "failure")
    return {
        "status": status,
        "reports_root": str(reports_root.resolve()),
        "message": f"{passed}/{total} scan(s) completed successfully.",
        "failed_count": failures,
        "total_count": total,
    }


def list_available_scans(credentials_file: str) -> dict:
    """List all scan names defined in a credentials YAML file.

    Args:
        credentials_file: Path to the YAML credentials file.

    Returns:
        dict with keys:
            status - "success" | "failure"
            scans  - list of dicts with name and provider for each scan entry
            message - error message if status is failure
    """
    creds_path = Path(credentials_file)
    if not creds_path.exists():
        return {"status": "failure", "scans": [], "message": f"File not found: {credentials_file}"}

    try:
        config = load_config(creds_path)
    except Exception as exc:
        return {"status": "failure", "scans": [], "message": str(exc)}

    return {
        "status": "success",
        "scans": [{"name": s.name, "provider": s.provider} for s in config.scans],
        "message": f"{len(config.scans)} scan(s) available.",
    }


def find_report_directories(reports_root: str = "reports") -> dict:
    """List all ScoutSuite report directories under the reports root.

    Args:
        reports_root: Root directory where scan reports are saved (default: reports/).

    Returns:
        dict with keys:
            status       - "success" | "failure"
            report_dirs  - list of absolute paths to report directories, newest first
            message      - summary
    """
    root = Path(reports_root)
    if not root.exists():
        return {
            "status": "failure",
            "report_dirs": [],
            "message": f"Reports directory does not exist: {reports_root}",
        }

    # A valid report dir contains the ScoutSuite results JS file somewhere inside
    dirs = sorted(
        [d for d in root.iterdir() if d.is_dir() and _has_results_file(d)],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    paths = [str(d.resolve()) for d in dirs]
    return {
        "status": "success",
        "report_dirs": paths,
        "message": f"Found {len(paths)} report directory(ies).",
    }


def _has_results_file(directory: Path) -> bool:
    return bool(list(directory.rglob("scoutsuite_results*.js")))
