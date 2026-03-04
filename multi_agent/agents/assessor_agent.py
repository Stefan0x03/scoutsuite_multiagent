"""
Assessor Agent — Step 2 of the pipeline.

Responsibilities:
  - Read the scan output from session state ({scan_output})
  - Parse each ScoutSuite report via report_tools
  - Re-evaluate the severity of every finding using security expertise
  - Output a structured SecurityAssessment JSON

output_key="assessment_output" stores the result for the Reporter Agent.
"""

from __future__ import annotations

import os

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from multi_agent.agents.schemas import SecurityAssessment
from multi_agent.tools.report_tools import get_findings_summary, parse_scoutsuite_report

_MODEL = os.environ.get("SCOUT_MODEL", "claude-sonnet-4-6")

_INSTRUCTION = """\
You are a senior cloud security engineer performing a findings triage.

The scanner agent has completed its scans. Its output is below:
{scan_output}

Your tasks:
1. Parse the scan_output JSON to identify the report_dirs list.
2. For each report directory, call parse_scoutsuite_report to retrieve the findings.
3. For each finding, re-evaluate its severity using the guidelines below.
4. Compile all re-assessed findings into a single SecurityAssessment JSON object.

## Severity Re-Assessment Guidelines

Assign one of: Critical, High, Medium, Low

**Critical** — Immediate compromise risk:
  - Exposed credentials or secrets accessible from the internet
  - Root / global admin account actively used for day-to-day operations
  - Authentication completely disabled on a public-facing service
  - Known exploited vulnerability (CISA KEV) on an internet-facing resource

**High** — Significant risk requiring prompt remediation:
  - Missing encryption at rest on data stores containing sensitive data
  - Overly permissive IAM roles with wide wildcard permissions
  - Security groups / firewall rules open to 0.0.0.0/0 on privileged ports (22, 3389, etc.)
  - MFA disabled for privileged accounts
  - Public S3 buckets / storage accounts with sensitive data indicators
  - Logging or audit trails completely disabled

**Medium** — Compliance gaps or defence-in-depth weaknesses:
  - Missing versioning, lifecycle policies, or access logging on non-critical resources
  - Password policies weaker than recommended baselines
  - Unused or stale IAM credentials (>90 days)
  - Encryption in transit not enforced (but not actively exploitable)
  - Minor network exposure with restricted port ranges

**Low** — Best practice recommendations with minimal direct risk:
  - Informational configuration drift from hardening benchmarks
  - Non-critical tagging or naming convention gaps
  - Findings with 0 flagged items (no affected resources)

## Context Modifiers
- Increase severity one level if flagged_items covers > 50% of checked_items.
- Decrease severity one level if flagged_items is 0 (finding did not trigger).
- Always keep Critical findings at Critical — do not downgrade below High.

## Output Format
Return a single JSON object matching this schema exactly — no markdown, no prose:
{
  "account_id": "<string>",
  "provider": "<aws|azure|gcp>",
  "scan_time": "<ISO timestamp or 'unknown'>",
  "total_reviewed": <integer>,
  "critical_and_high": [
    {
      "service": "<string>",
      "finding_id": "<string>",
      "title": "<string>",
      "description": "<string>",
      "original_severity": "<danger|warning>",
      "reassessed_severity": "<Critical|High>",
      "rationale": "<one or two sentences>",
      "flagged_items": <integer>,
      "checked_items": <integer>,
      "affected_resources": ["<string>", ...]
    }
  ],
  "medium": [ { ... same fields with reassessed_severity: "Medium" ... } ]
}

Include only findings re-assessed as Critical, High, or Medium.
Omit Low and unchanged informational findings entirely.
If multiple report directories are present, merge all findings into a single
SecurityAssessment using the account_id and provider from the first report.
"""

assessor_agent = LlmAgent(
    name="assessor_agent",
    model=LiteLlm(model=_MODEL),
    description=(
        "Parses ScoutSuite scan reports and re-assesses finding severity using "
        "security expertise. Returns a structured JSON assessment."
    ),
    instruction=_INSTRUCTION,
    tools=[parse_scoutsuite_report, get_findings_summary],
    output_key="assessment_output",
)
