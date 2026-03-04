"""
Scan orchestration — iterates over credential entries, builds commands,
and runs ScoutSuite as a subprocess for each one.
"""

from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .command import build_command
from .config import ScanEntry
from .logger import masking_filter

log = logging.getLogger(__name__)

# Fields whose values are secrets and must be masked before any logging
_SECRET_FIELDS = {
    "secret_access_key",
    "session_token",
    "client_secret",
}


def _register_secrets(auth: object) -> None:
    """Feed all secret field values into the masking filter."""
    for field, value in auth.model_dump().items():
        if field in _SECRET_FIELDS and value:
            masking_filter.register(str(value))


def _safe_auth_label(auth: object) -> str:
    """Return a loggable description of the auth method with no secret values."""
    t = getattr(auth, "type", "unknown")
    if t == "access_keys":
        # Show only first 6 chars of the key ID as an identifier
        return f"access_keys (key_id={auth.access_key_id[:6]}...)"
    if t == "profile":
        return f"profile ({auth.profile_name})"
    if t == "role":
        return f"role ({auth.role_arn})"
    if t == "service_principal":
        return f"service_principal (client_id={auth.client_id})"
    if t == "cli":
        sub = f" subscription={auth.subscription_id}" if auth.subscription_id else ""
        return f"cli{sub}"
    if t == "service_account":
        return f"service_account (key_file={auth.key_file})"
    if t == "user_account":
        return "user_account"
    return t


def _output_dir(reports_root: Path, name: str) -> Path:
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = name.lower().replace(" ", "-").replace("/", "-")
    return reports_root / f"{safe_name}_{timestamp}"


def run_scan(entry: ScanEntry, reports_root: Path) -> bool:
    """
    Execute a single ScoutSuite scan.

    Returns True on success (exit code 0), False on failure or error.
    Secrets are registered with the masking filter before any log output.
    """
    # Register secrets FIRST — before any log line that might include auth info
    _register_secrets(entry.auth)

    output_dir = _output_dir(reports_root, entry.name)
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info(
        "[%s] Starting scan  provider=%s  auth=%s",
        entry.name, entry.provider, _safe_auth_label(entry.auth),
    )
    log.info("[%s] Report output: %s", entry.name, output_dir)

    cmd = build_command(entry, output_dir)

    # Log argument count only — never log the full command (contains secrets)
    log.debug("[%s] Command: scout %s  (%d args total)", entry.name, entry.provider, len(cmd))

    log.debug(cmd)

    try:
        result = subprocess.run(
            cmd,
            # Stream ScoutSuite's real-time progress directly to the terminal
            capture_output=False,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        log.error(
            "[%s] 'scout' executable not found. "
            "Install ScoutSuite: pip install scoutsuite",
            entry.name,
        )
        return False
    except Exception as exc:
        log.error("[%s] Unexpected error launching scout: %s", entry.name, exc)
        return False

    if result.returncode == 0:
        log.info("[%s] Scan completed successfully.", entry.name)
        return True

    log.error("[%s] Scan failed (exit code %d).", entry.name, result.returncode)
    return False


def run_all(scans: list[ScanEntry], reports_root: Path) -> int:
    """
    Run all scans sequentially.

    Returns the number of failed scans (0 = all succeeded).
    """
    total = len(scans)
    failures = 0

    for i, entry in enumerate(scans, start=1):
        log.info("")
        log.info("=" * 60)
        log.info("Scan %d / %d  —  %s", i, total, entry.name)
        log.info("=" * 60)

        if not run_scan(entry, reports_root):
            failures += 1

    log.info("")
    log.info("=" * 60)
    passed = total - failures
    if failures == 0:
        log.info("All %d scan(s) completed successfully.", total)
    else:
        log.warning("%d / %d scan(s) failed.", failures, total)
    log.info("Reports saved under: %s", reports_root.resolve())
    log.info("=" * 60)

    return failures
