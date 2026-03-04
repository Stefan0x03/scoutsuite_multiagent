"""
ScoutSuite command builders — one function per provider.

Each builder receives a validated auth model and an output directory and
returns a list[str] ready for subprocess.run().  Secrets appear only in
the list itself; they are never formatted into log messages.

ScoutSuite CLI reference (v5.x):
  scout aws  --access-keys --access-key-id <id> --secret-access-key <s> [--session-token <t>]
  scout aws  --profile <name>
  scout azure --service-principal --tenant <t> --subscription-id <s> --client-id <c> --client-secret <s>
  scout azure --cli [--subscription-id <s>]
  scout gcp  --service-account --key-file <path> [--project-id <id>]
  scout gcp  --user-account [--project-id <id>]
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import (
        AwsAccessKeysAuth,
        AwsProfileAuth,
        AwsRoleAuth,
        AzureCliAuth,
        AzureServicePrincipalAuth,
        GcpServiceAccountAuth,
        GcpUserAccountAuth,
        ScanEntry,
    )


def _aws_command(auth: object, output_dir: Path) -> list[str]:
    base = ["scout", "aws", "--report-dir", str(output_dir), "--no-browser"]

    if auth.type == "access_keys":
        cmd = base + [
            "--access-keys",
            "--access-key-id", auth.access_key_id,
            "--secret-access-key", auth.secret_access_key,
        ]
        if auth.session_token:
            cmd += ["--session-token", auth.session_token]
        return cmd

    if auth.type == "profile":
        return base + ["--profile", auth.profile_name]

    if auth.type == "role":
        # ScoutSuite assumes the role via its own --role-arn flag
        cmd = base + ["--role-arn", auth.role_arn]
        if auth.source_profile:
            cmd += ["--profile", auth.source_profile]
        elif auth.access_key_id and auth.secret_access_key:
            cmd += [
                "--access-keys",
                "--access-key-id", auth.access_key_id,
                "--secret-access-key", auth.secret_access_key,
            ]
            if auth.session_token:
                cmd += ["--session-token", auth.session_token]
        if auth.external_id:
            cmd += ["--external-id", auth.external_id]
        return cmd

    raise ValueError(f"Unknown AWS auth type: {auth.type}")


def _azure_command(auth: object, output_dir: Path) -> list[str]:
    base = ["scout", "azure", "--report-dir", str(output_dir), "--no-browser"]

    if auth.type == "service_principal":
        return base + [
            "--service-principal",
            "--tenant", auth.tenant_id,
            "--subscription-id", auth.subscription_id,
            "--client-id", auth.client_id,
            "--client-secret", auth.client_secret,
        ]

    if auth.type == "cli":
        cmd = base + ["--cli"]
        if auth.subscription_id:
            cmd += ["--subscription-id", auth.subscription_id]
        return cmd

    raise ValueError(f"Unknown Azure auth type: {auth.type}")


def _gcp_command(auth: object, output_dir: Path) -> list[str]:
    base = ["scout", "gcp", "--report-dir", str(output_dir), "--no-browser"]

    if auth.type == "service_account":
        cmd = base + ["--service-account", "--key-file", str(auth.key_file)]
        if auth.project_id:
            cmd += ["--project-id", auth.project_id]
        return cmd

    if auth.type == "user_account":
        cmd = base + ["--user-account"]
        if auth.project_id:
            cmd += ["--project-id", auth.project_id]
        return cmd

    raise ValueError(f"Unknown GCP auth type: {auth.type}")


_BUILDERS = {
    "aws": _aws_command,
    "azure": _azure_command,
    "gcp": _gcp_command,
}


def build_command(entry: "ScanEntry", output_dir: Path) -> list[str]:
    """Return the ScoutSuite argv list for a scan entry."""
    builder = _BUILDERS.get(entry.provider)
    if builder is None:
        raise ValueError(f"Unsupported provider: {entry.provider!r}")
    return builder(entry.auth, output_dir)
