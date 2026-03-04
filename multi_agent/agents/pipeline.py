"""
Security Audit Pipeline — SequentialAgent orchestrating all three agents.

Execution order:
  1. scanner_agent  — runs ScoutSuite scans, stores report dir in state
  2. assessor_agent — parses reports, re-assesses severity, stores JSON in state
  3. reporter_agent — formats Markdown report from the structured assessment

Data flows via session state:
  scanner_agent  → state["scan_output"]       → assessor_agent instruction
  assessor_agent → state["assessment_output"] → reporter_agent instruction
"""

from __future__ import annotations

from google.adk.agents import SequentialAgent

from multi_agent.agents.assessor_agent import assessor_agent
from multi_agent.agents.reporter_agent import reporter_agent
from multi_agent.agents.scanner_agent import scanner_agent

security_audit_pipeline = SequentialAgent(
    name="security_audit_pipeline",
    description=(
        "Multi-agent pipeline that runs ScoutSuite cloud security scans, "
        "re-assesses finding severity using AI, and produces a prioritised "
        "Markdown security report."
    ),
    sub_agents=[scanner_agent, assessor_agent, reporter_agent],
)