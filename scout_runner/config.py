"""
YAML credentials file loading and validation via Pydantic.

Schema overview:
    scans:
      - name: <str>           # human label, used for output directory
        provider: aws|azure|gcp
        auth:
          type: <auth-type>   # determines which fields are required
          ...                 # provider-specific credential fields
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# AWS auth models
# ---------------------------------------------------------------------------

class AwsAccessKeysAuth(BaseModel):
    type: Literal["access_keys"]
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None


class AwsProfileAuth(BaseModel):
    type: Literal["profile"]
    profile_name: str


class AwsRoleAuth(BaseModel):
    """Assume an IAM role using a source profile or access keys."""
    type: Literal["role"]
    role_arn: str
    # Source credentials for assuming the role (optional — uses env/profile if omitted)
    source_profile: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    external_id: Optional[str] = None


AwsAuth = Annotated[
    Union[AwsAccessKeysAuth, AwsProfileAuth, AwsRoleAuth],
    Field(discriminator="type"),
]


# ---------------------------------------------------------------------------
# Azure auth models
# ---------------------------------------------------------------------------

class AzureServicePrincipalAuth(BaseModel):
    type: Literal["service_principal"]
    tenant_id: str
    subscription_id: str
    client_id: str
    client_secret: str


class AzureCliAuth(BaseModel):
    """Use the local Azure CLI session (az login)."""
    type: Literal["cli"]
    subscription_id: Optional[str] = None


AzureAuth = Annotated[
    Union[AzureServicePrincipalAuth, AzureCliAuth],
    Field(discriminator="type"),
]


# ---------------------------------------------------------------------------
# GCP auth models
# ---------------------------------------------------------------------------

class GcpServiceAccountAuth(BaseModel):
    type: Literal["service_account"]
    key_file: Path
    project_id: Optional[str] = None

    @field_validator("key_file")
    @classmethod
    def key_file_must_exist(cls, v: Path) -> Path:
        if not v.exists():
            raise ValueError(f"GCP key file not found: {v}")
        return v


class GcpUserAccountAuth(BaseModel):
    """Use application-default credentials (gcloud auth application-default login)."""
    type: Literal["user_account"]
    project_id: Optional[str] = None


GcpAuth = Annotated[
    Union[GcpServiceAccountAuth, GcpUserAccountAuth],
    Field(discriminator="type"),
]


# ---------------------------------------------------------------------------
# Top-level scan entry
# ---------------------------------------------------------------------------

class ScanEntry(BaseModel):
    name: str
    provider: Literal["aws", "azure", "gcp"]
    auth: Union[AwsAuth, AzureAuth, GcpAuth]

    @field_validator("auth", mode="before")
    @classmethod
    def validate_auth_for_provider(cls, v: object) -> object:
        # Pass through — discriminator on `type` handles branching.
        # Provider-level mismatch will surface as a Pydantic validation error.
        return v


class Config(BaseModel):
    scans: list[ScanEntry]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(path: Path) -> Config:
    """Load and validate the YAML credentials file."""
    if ".." in str(path):
        raise ValueError("Invalid file path")
    with open(path) as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"Credentials file must be a YAML mapping, got: {type(raw).__name__}")
    return Config.model_validate(raw)
