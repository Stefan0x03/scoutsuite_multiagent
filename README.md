# ScoutSuite Multi-Agent Security Auditor

An AI-powered cloud security auditing pipeline that combines [ScoutSuite](https://github.com/nccgroup/ScoutSuite) with a three-agent LLM workflow to produce prioritized, actionable security reports across AWS, Azure, and GCP.

## How It Works

The pipeline runs three specialized agents in sequence:

```
credentials.yaml
      │
      ▼
┌─────────────────┐
│  Scanner Agent  │  Runs ScoutSuite against each cloud account
└────────┬────────┘
         │ scan_output (report dirs)
         ▼
┌─────────────────┐
│ Assessor Agent  │  Parses findings, re-assesses severity with context
└────────┬────────┘
         │ assessment_output (structured JSON)
         ▼
┌─────────────────┐
│ Reporter Agent  │  Formats Markdown report with remediation guidance
└────────┬────────┘
         │
         ▼
   report.md
```

1. **Scanner Agent** — Calls `scout` for each cloud account in your credentials file, collects report directories, and stores paths in session state. Supports skipping scans to re-analyze existing reports.

2. **Assessor Agent** — Parses each `scoutsuite_results*.js` report, reviews all `danger`/`warning` findings, and re-assesses severity using security expertise and context modifiers (e.g. upgrades severity when >50% of resources are flagged, downgrades when 0 resources are affected). Outputs a structured `SecurityAssessment`.

3. **Reporter Agent** — Reads the structured assessment and generates a Markdown report with an executive summary, critical/high findings with verification CLI commands, medium findings, and prioritized next steps.

## Prerequisites

- Python 3.11+
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) installed and `scout` on your PATH
- An LLM API key (Anthropic, OpenAI, etc.)
- Cloud credentials with read access to the accounts you want to audit

## Installation

```bash
# Clone the repo
git clone <repo-url>
cd scoutsuite_multiagent

# Create a virtual environment
python -m venv .env
source .env/bin/activate

# Install dependencies
pip install scoutsuite pydantic pyyaml google-adk litellm
```

> **Note:** The `requirements.txt` has known dependency conflicts. Install packages manually as shown above.

## Configuration

### Credentials File

Create a YAML file listing the cloud accounts to scan:

```yaml
# credentials.yaml
scans:
  - name: aws-prod
    provider: aws
    auth:
      type: profile          # access_keys | profile | role
      profile_name: prod

  - name: aws-dev
    provider: aws
    auth:
      type: access_keys
      access_key_id: AKIA...
      secret_access_key: ...
      # session_token: ...   # optional, for temporary credentials

  - name: azure-corp
    provider: azure
    auth:
      type: service_principal   # service_principal | cli
      tenant_id: "00000000-..."
      subscription_id: "00000000-..."
      client_id: "00000000-..."
      client_secret: "..."

  - name: gcp-main
    provider: gcp
    auth:
      type: service_account    # service_account | user_account
      key_file: /path/to/key.json
      project_id: my-project
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | If using Claude | Anthropic API key |
| `OPENAI_API_KEY` | If using OpenAI | OpenAI API key |
| `SCOUT_MODEL` | No | LiteLLM model string (default: `claude-sonnet-4-6`) |

The `SCOUT_MODEL` variable accepts any [LiteLLM model string](https://docs.litellm.ai/docs/providers):

```bash
export SCOUT_MODEL=claude-sonnet-4-6          # Anthropic (default)
export SCOUT_MODEL=gpt-4o                     # OpenAI
export SCOUT_MODEL=azure/gpt-4o               # Azure OpenAI
export SCOUT_MODEL=ollama/llama3              # Local Ollama
```

## Usage

### Full Audit (scan + assess + report)

```bash
# Audit all accounts in credentials.yaml
python -m multi_agent -c credentials.yaml

# Save the report to a file
python -m multi_agent -c credentials.yaml -o report.md

# Scan only specific accounts
python -m multi_agent -c credentials.yaml --scans "aws-prod,azure-corp"

# Use a custom reports output directory
python -m multi_agent -c credentials.yaml -r ./scan-results -o report.md
```

### Re-analyze Existing Scans

Skip the scanning step and use a previously generated ScoutSuite report directory:

```bash
python -m multi_agent --skip-scan --existing-report ./scan-results -o report.md
```

### Batch Scanning Only

Run ScoutSuite scans without the LLM analysis:

```bash
# Scan all accounts
python -m scout_runner -c credentials.yaml

# Scan specific accounts
python -m scout_runner -c credentials.yaml --only aws-prod azure-corp

# Preview without executing
python -m scout_runner -c credentials.yaml --dry-run

# Verbose logging
python -m scout_runner -c credentials.yaml -v
```

## Output

The final report is a Markdown document structured as:

- **Executive Summary** — account, provider, scan date, finding counts by severity
- **Critical & High Findings** — full details per finding including:
  - Re-assessed severity with rationale
  - Affected resources (up to 20)
  - Verification steps (CLI commands)
  - Remediation guidance with links to cloud provider docs
- **Medium Findings** — summarized list (detailed if ≤10, condensed if more)
- **Next Steps** — prioritized remediation actions ranked by risk reduction impact

## Project Structure

```
scoutsuite_multiagent/
├── multi_agent/
│   ├── main.py                  # CLI entry point, ADK runner setup
│   ├── agents/
│   │   ├── pipeline.py          # SequentialAgent orchestrator
│   │   ├── scanner_agent.py     # Step 1: run ScoutSuite scans
│   │   ├── assessor_agent.py    # Step 2: parse and re-assess findings
│   │   ├── reporter_agent.py    # Step 3: generate Markdown report
│   │   └── schemas.py           # Pydantic models (ReassessedFinding, SecurityAssessment)
│   └── tools/
│       ├── scan_tools.py        # run_scoutsuite_scan, list_available_scans, find_report_directories
│       └── report_tools.py      # parse_scoutsuite_report, get_findings_summary
└── scout_runner/
    ├── main.py                  # Batch scanner CLI
    ├── config.py                # Pydantic config models for AWS/Azure/GCP auth
    ├── runner.py                # Scan orchestration, subprocess execution
    ├── command.py               # ScoutSuite CLI command builders per provider
    └── logger.py                # Credential masking filter for logs
```

## Security Notes

- All credentials are validated via Pydantic before use and never written to logs.
- A `MaskingFilter` intercepts all log output and replaces registered secret strings with `***REDACTED***`.
- ScoutSuite subprocess output is streamed directly to the terminal; credentials are injected into the command list only (never formatted into log strings).
- The credentials YAML file should be treated as a secret and not committed to source control.
