"""
Pydantic models used as output_schema for structured agent responses.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReassessedFinding(BaseModel):
    service: str = Field(description="Cloud service name, e.g. iam, ec2, s3, storage")
    finding_id: str = Field(description="ScoutSuite finding identifier")
    title: str = Field(description="Short human-readable title")
    description: str = Field(description="What was found and why it matters")
    original_severity: str = Field(description="ScoutSuite original level: danger or warning")
    reassessed_severity: str = Field(
        description="Re-assessed severity: Critical, High, Medium, or Low"
    )
    rationale: str = Field(description="Why this severity was assigned")
    flagged_items: int = Field(description="Number of affected resources")
    checked_items: int = Field(description="Total resources checked for this finding")
    affected_resources: list[str] = Field(
        default_factory=list,
        description="List of affected resource identifiers (up to 20)",
    )


class SecurityAssessment(BaseModel):
    account_id: str = Field(description="Cloud account or project identifier")
    provider: str = Field(description="Cloud provider: aws, azure, or gcp")
    scan_time: str = Field(description="When the scan was performed")
    total_reviewed: int = Field(description="Total number of findings reviewed")
    critical_and_high: list[ReassessedFinding] = Field(
        default_factory=list,
        description="Findings re-assessed as Critical or High severity",
    )
    medium: list[ReassessedFinding] = Field(
        default_factory=list,
        description="Findings re-assessed as Medium severity",
    )
