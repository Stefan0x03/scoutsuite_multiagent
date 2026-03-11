"""
CLI entry point for the ScoutSuite multi-agent security auditor.

Usage:
    python -m multi_agent [options]

Environment variables:
    SCOUT_MODEL       LiteLLM model string (default: claude-sonnet-4-6)
                      Examples: gpt-4o, anthropic/claude-3-5-sonnet-20241022,
                                ollama/llama3, azure/gpt-4o
    ANTHROPIC_API_KEY Required if using Claude models
    OPENAI_API_KEY    Required if using OpenAI models
    (any other LiteLLM-supported provider env vars)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from multi_agent.agents.pipeline import security_audit_pipeline

APP_NAME = "scoutsuite_auditor"
USER_ID = "operator"
SESSION_ID = "testSession01"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scout-agent",
        description="AI-powered ScoutSuite cloud security auditor (multi-agent pipeline).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all accounts in credentials.yaml
  python -m multi_agent -c credentials.yaml

  # Audit specific named scans only
  python -m multi_agent -c credentials.yaml --scans "aws-prod,azure-corp"

  # Use a different LLM model (overrides SCOUT_MODEL env var)
  SCOUT_MODEL=gpt-4o python -m multi_agent -c credentials.yaml

  # Save the Markdown report to a file
  python -m multi_agent -c credentials.yaml --output report.md
        """,
    )
    parser.add_argument(
        "-c", "--credentials",
        type=Path,
        default=Path("credentials.yaml"),
        metavar="PATH",
        help="YAML credentials file (default: credentials.yaml)",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports"),
        metavar="PATH",
        help="Root directory for ScoutSuite reports (default: reports/)",
    )
    parser.add_argument(
        "--scans",
        default="",
        metavar="NAMES",
        help="Comma-separated scan names to run (default: all scans in file)",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        metavar="FILE",
        help="Save the Markdown report to this file (default: print to stdout)",
    )
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help=(
            "Skip the scanning step and assess an existing report directory. "
            "Requires --report-dir to point to an existing scan."
        ),
    )
    parser.add_argument(
        "--existing-report",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to an existing ScoutSuite report directory (used with --skip-scan).",
    )
    return parser.parse_args(argv)


def _build_prompt(args: argparse.Namespace) -> str:
    """Build the initial user message that kicks off the pipeline."""
    if args.skip_scan and args.existing_report:
        # Pre-fill scan_output so the scanner_agent is bypassed gracefully
        scan_output = json.dumps({
            "status": "success",
            "reports_root": str(args.existing_report.parent.resolve()),
            "report_dirs": [str(args.existing_report.resolve())],
            "message": "Using existing report (scan step skipped).",
        })
        return (
            f"Assess this existing ScoutSuite report and produce a security findings report.\n"
            f"Scan output context: {scan_output}\n"
            f"Report directory: {args.existing_report}"
        )

    parts = [
        f"Run a cloud security audit using the credentials file at: {args.credentials.resolve()}",
        f"Store reports in: {args.reports_dir.resolve()}",
    ]
    if args.scans:
        parts.append(f"Run only these scans: {args.scans}")
    parts.append(
        "After scanning, re-assess the severity of all findings and produce a "
        "prioritised Markdown security report covering Critical, High, and Medium findings."
    )
    return "\n".join(parts)


async def _run_pipeline(prompt: str, output_file: Path | None) -> None:
    session_service = InMemorySessionService()

    runner = Runner(
        agent=security_audit_pipeline,
        app_name=APP_NAME,
        session_service=session_service,
    )

    session = await session_service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=SESSION_ID)
    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    final_report: str | None = None

    print("\n[*] Starting security audit pipeline...\n", flush=True)

    async for event in runner.run_async(
        user_id=USER_ID,
        session_id=SESSION_ID,
        new_message=message,
    ):
        # Stream intermediate agent activity to stderr so it doesn't pollute the report
        if hasattr(event, "content") and event.content and not event.is_final_response():
            for part in event.content.parts or []:
                if hasattr(part, "text") and part.text:
                    print(f"[agent] {part.text[:120]}...", file=sys.stderr, flush=True)

        if event.is_final_response():
            if event.content and event.content.parts:
                final_report = event.content.parts[0].text

    if not final_report:
        print("[!] Pipeline completed but produced no output.", file=sys.stderr)
        sys.exit(1)

    if output_file:
        output_file.write_text(final_report, encoding="utf-8")
        print(f"\n[*] Report saved to: {output_file.resolve()}", flush=True)
    else:
        print("\n" + "=" * 70)
        print(final_report)
        print("=" * 70)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    if not args.skip_scan and not args.credentials.exists():
        print(f"[!] Credentials file not found: {args.credentials}", file=sys.stderr)
        sys.exit(1)

    if args.skip_scan and (args.existing_report is None or not args.existing_report.exists()):
        print(
            "[!] --skip-scan requires --existing-report pointing to a valid directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    prompt = _build_prompt(args)
    asyncio.run(_run_pipeline(prompt, args.output))


if __name__ == "__main__":
    main()
