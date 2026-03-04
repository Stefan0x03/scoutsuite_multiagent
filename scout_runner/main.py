"""
CLI entry point for the ScoutSuite batch scanner.

Usage:
    python -m scout_runner [options]

Options:
    -c, --credentials PATH   YAML credentials file  (default: credentials.yaml)
    -o, --reports-dir PATH   Root directory for scan reports  (default: reports/)
    --only NAME [NAME ...]   Run only scans whose name matches one of these values
    -v, --verbose            Enable debug logging
    --dry-run                Print what would be scanned without running anything
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from pydantic import ValidationError

from .config import load_config
from .logger import setup_logging
from .runner import run_all

log = logging.getLogger(__name__)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scout-runner",
        description="Run ScoutSuite security scans from a YAML credentials file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all accounts in credentials.yaml
  python -m scout_runner

  # Use a custom credentials file and output directory
  python -m scout_runner -c ./my-creds.yaml -o ./scan-results

  # Scan only specific accounts by name
  python -m scout_runner --only "aws-prod" "azure-corp"

  # Dry run — list what would be scanned
  python -m scout_runner --dry-run
        """,
    )
    parser.add_argument(
        "-c", "--credentials",
        type=Path,
        default=Path("credentials.yaml"),
        metavar="PATH",
        help="Path to the YAML credentials file (default: credentials.yaml)",
    )
    parser.add_argument(
        "-o", "--reports-dir",
        type=Path,
        default=Path("reports"),
        metavar="PATH",
        help="Root directory for scan reports (default: reports/)",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="NAME",
        help="Run only scans whose name matches one of these values",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be scanned without executing anything",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    setup_logging(debug=args.verbose)

    # Validate credentials file exists
    if not args.credentials.exists():
        log.error("Credentials file not found: %s", args.credentials)
        sys.exit(1)

    # Load and validate config
    try:
        config = load_config(args.credentials)
    except ValidationError as exc:
        log.error("Invalid credentials file:\n%s", exc)
        sys.exit(1)
    except Exception as exc:
        log.error("Failed to load credentials file: %s", exc)
        sys.exit(1)

    scans = config.scans

    # Apply --only filter
    if args.only:
        wanted = set(args.only)
        scans = [s for s in scans if s.name in wanted]
        if not scans:
            log.error(
                "No scans matched --only filter %s. "
                "Available names: %s",
                list(wanted),
                [s.name for s in config.scans],
            )
            sys.exit(1)

    if not scans:
        log.warning("No scans defined in %s. Nothing to do.", args.credentials)
        sys.exit(0)

    # Dry-run: list scans and exit
    if args.dry_run:
        log.info("Dry run — scans that would execute:")
        for i, entry in enumerate(scans, start=1):
            log.info("  %d. %s  [%s]", i, entry.name, entry.provider)
        sys.exit(0)

    log.info("Loaded %d scan(s) from %s", len(scans), args.credentials)

    failures = run_all(scans, args.reports_dir)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
