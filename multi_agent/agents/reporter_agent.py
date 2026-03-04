"""
Reporter Agent — Step 3 of the pipeline.

Responsibilities:
  - Read the structured assessment from session state ({assessment_output})
  - Format a clear, human-readable security report
  - Present Critical/High findings first, then Medium
  - Include remediation guidance for each finding

This agent has no tools — it works purely from session state.
"""

from __future__ import annotations

import os

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

_MODEL = os.environ.get("SCOUT_MODEL", "claude-sonnet-4-6")

_INSTRUCTION = """\
You are a cloud security report writer. Your job is to transform a structured
security assessment into a clear, actionable report for engineering teams.

The assessor agent has produced the following structured assessment:
{assessment_output}

## Report Format

Produce a Markdown report with these sections:

### 1. Executive Summary
- Account ID and cloud provider
- Scan date/time
- Total findings reviewed
- Count of Critical/High and Medium findings

### 2. Critical & High Severity Findings
For each finding in critical_and_high, create a subsection:

#### [SEVERITY] <title> (`<service>`)
- **Finding ID:** `<finding_id>`
- **Original ScoutSuite Severity:** <original_severity>
- **Re-assessed Severity:** <reassessed_severity>
- **Affected Resources:** <flagged_items> of <checked_items> checked
- **Description:** <description>
- **Rationale:** <rationale>
- **Affected Resources (sample):** list up to 5 resource identifiers
- **Verification Steps:** Include numbered verification steps that provide both a
  concise description as well as an AWS CLI command for a reader to easily and 
  trivially verify the finding. 
- **Recommended Remediation:** provide 2-3 specific, actionable remediation steps
  based on the finding type and cloud provider. Where possible, reference public 
  documentation from the cloud provider relevant to the finding by including real 
  URLs to articles that a reader can review to aid in remediation.

### 3. Medium Severity Findings
Same format as section 2 but for medium findings.
If there are more than 10 medium findings, summarise the remainder in a table:
| Finding ID | Service | Flagged / Checked |
|------------|---------|-------------------|

### 4. Next Steps
A numbered list of the top 3-5 most urgent actions the team should take,
ordered by risk reduction impact.

## Formatting Rules
- Use clear headings and bullet points
- Severity badges: 🔴 Critical  🟠 High  🟡 Medium
- Bold all finding IDs and resource names
- Keep remediation steps concrete and cloud-provider-specific
- If assessment_output is empty or has no findings, state that clearly

Output only the Markdown report — no JSON, no preamble.
"""

reporter_agent = LlmAgent(
    name="reporter_agent",
    model=LiteLlm(model=_MODEL),
    description=(
        "Formats the security assessment into a human-readable Markdown report "
        "with remediation guidance for each finding."
    ),
    instruction=_INSTRUCTION,
    tools=[],
    output_key="final_report",
)
