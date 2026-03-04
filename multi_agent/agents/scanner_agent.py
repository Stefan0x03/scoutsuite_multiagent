"""
Scanner Agent — Step 1 of the pipeline.

Responsibilities:
  - Accept a credentials file path and optional scan filter
  - Run ScoutSuite scans via the scan_tools
  - Return the reports root directory path so the next agent can locate results

output_key="scan_output" stores a JSON string with scan status and reports_root.
The assessor_agent reads this via {scan_output} in its instruction template.
"""

from __future__ import annotations

import os

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from multi_agent.tools.scan_tools import (
    find_report_directories,
    list_available_scans,
    run_scoutsuite_scan,
)

_MODEL = os.environ.get("SCOUT_MODEL", "claude-sonnet-4-6")

scanner_agent = LlmAgent(
    name="scanner_agent",
    model=LiteLlm(model=_MODEL),
    description=(
        "Runs ScoutSuite cloud security scans from a YAML credentials file. "
        "Returns the path to the reports directory containing scan results."
    ),
    instruction="""\
You are a cloud security scanner. Your job is to execute ScoutSuite scans and
report back the location of the generated reports.

Steps:
1. If you need to know what scans are available, call list_available_scans first.
2. Call run_scoutsuite_scan with the provided credentials_file path.
   - Pass scan_names only if the user asked to restrict to specific scans.
   - Use the default reports_dir ("reports") unless told otherwise.
3. After the scan completes, call find_report_directories to confirm which
   report directories were created.
4. Output a concise JSON summary with these keys:
   - status: "success", "partial_failure", or "failure"
   - reports_root: absolute path to the reports root directory
   - report_dirs: list of absolute paths to the individual report directories
   - message: one sentence describing what happened

Do not attempt to parse or interpret findings — that is the next agent's job.
Output only valid JSON, no markdown fences.
""",
    tools=[run_scoutsuite_scan, list_available_scans, find_report_directories],
    output_key="scan_output",
)
