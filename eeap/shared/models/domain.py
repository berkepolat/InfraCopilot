"""Pydantic mirrors of the JSON Schema contracts in shared/schemas.

The JSON Schemas are authoritative; tests/contract checks these models against them.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
FindingStatus = Literal["PASS", "FAIL", "WARNING", "INFO"]
Criticality = Literal["Critical", "High", "Medium", "Low"]
AssetType = Literal["Server", "Workstation", "DomainController", "NetworkDevice", "Database",
                    "Application", "CloudResource", "Identity", "Other"]
Environment = Literal["Production", "Staging", "Test", "Development", "DR"]
Tier = Literal["Tier0", "Tier1", "Tier2", "Unclassified"]
RelationshipType = Literal["MemberOf", "AdministrativeAccess", "Delegation", "AuthenticationRisk",
                           "RemoteAccess", "PrivilegedAccess"]

ASSET_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
CONTROL_ID_PATTERN = r"^[A-Z]{2,8}-[0-9]{3,4}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssetCreate(_Strict):
    asset_id: str = Field(pattern=ASSET_ID_PATTERN)
    hostname: str = Field(min_length=1, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    asset_type: AssetType
    criticality: Criticality = "Medium"
    criticality_locked: bool = False
    tier: Tier = "Unclassified"
    owner: str | None = None
    environment: Environment = "Production"
    os_family: Literal["Windows", "Linux", "macOS", "NetworkOS", "Other"] | None = None
    os_version: str | None = None
    domain: str | None = None
    tags: list[str] = Field(default_factory=list, max_length=50)
    attributes: dict = Field(default_factory=dict)


class Asset(AssetCreate):
    owner_id: UUID | None = None
    status: Literal["active", "discovered", "retired"] = "active"
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class Finding(_Strict):
    finding_id: UUID
    asset_id: str = Field(pattern=ASSET_ID_PATTERN)
    control_id: str = Field(pattern=CONTROL_ID_PATTERN)
    control_name: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=100)
    severity: Severity
    status: FindingStatus
    evidence: dict
    recommendation: str = Field(max_length=8000)
    raw_data: dict
    created_at: datetime
    fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    subject_key: str | None = None
    lifecycle_state: Literal["open", "acknowledged", "in_remediation", "resolved",
                             "risk_accepted", "false_positive"] | None = None
    raw_data_ref: UUID | None = None
    source: Literal["server", "agent", "import"] | None = None
    source_tool: str | None = None
    run_id: UUID | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    updated_at: datetime | None = None


class Relationship(_Strict):
    source: str
    relationship: RelationshipType
    target: str
    properties: dict = Field(default_factory=dict)
    origin: Literal["collector", "import", "derived"] = "collector"


class EventEnvelope(_Strict):
    event_id: UUID
    type: str = Field(pattern=r"^[a-z]+\.[a-z_]+$")
    schema_version: int = Field(ge=1)
    source: str
    occurred_at: datetime
    correlation_id: str
    causation_id: UUID | None = None
    subject: str | None = None
    actor: dict | None = None
    data: dict
    data_ref: dict | None = None
