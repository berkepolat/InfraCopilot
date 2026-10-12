"""Pure finding logic: import parsing/validation, fingerprinting and lifecycle rules."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from eeap_shared.models.domain import ASSET_ID_PATTERN, CONTROL_ID_PATTERN, FindingStatus, Severity

SourceType = Literal["eeap_json", "eeap_csv"]
CONTENT_TYPES: dict[str, tuple[str, ...]] = {
    "eeap_json": ("application/json",),
    "eeap_csv": ("text/csv", "application/csv"),
}
MAX_RAW_DATA_BYTES = 64 * 1024
MAX_REPORTED_ERRORS = 50

LifecycleState = Literal["open", "acknowledged", "in_remediation", "resolved", "risk_accepted", "false_positive"]
GATING_STATES = frozenset({"open", "acknowledged", "in_remediation"})

# Manual triage transitions. risk_accepted is entered only through a risk acceptance record, and
# resolved only when a reassessment or import observes PASS.
TRIAGE_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"acknowledged", "in_remediation", "false_positive"}),
    "acknowledged": frozenset({"open", "in_remediation", "false_positive"}),
    "in_remediation": frozenset({"open", "acknowledged", "false_positive"}),
    "resolved": frozenset({"open"}),
    "false_positive": frozenset({"open"}),
    "risk_accepted": frozenset({"open"}),
}
RISK_ACCEPTABLE_FROM = frozenset({"open", "acknowledged", "in_remediation"})


class ImportRow(BaseModel):
    """One finding in the Standard Finding Format as accepted from imports."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    asset_id: str = Field(pattern=ASSET_ID_PATTERN)
    control_id: str = Field(pattern=CONTROL_ID_PATTERN)
    status: FindingStatus
    severity: Severity | None = None
    control_name: str | None = Field(default=None, max_length=200)
    category: str | None = Field(default=None, max_length=100)
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str | None = Field(default=None, max_length=4000)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    subject_key: str = Field(default="", max_length=512)
    source_tool: str | None = Field(default=None, max_length=100)

    @field_validator("evidence", mode="before")
    @classmethod
    def _evidence_text(cls, value: Any) -> Any:
        if value is None or value == "":
            return {}
        if isinstance(value, str):
            return {"summary": value[:4000]}
        return value

    @field_validator("raw_data", mode="before")
    @classmethod
    def _raw_data(cls, value: Any) -> Any:
        if value is None or value == "":
            return {}
        if isinstance(value, str):
            value = json.loads(value)
        if len(json.dumps(value, default=str)) > MAX_RAW_DATA_BYTES:
            raise ValueError("raw_data exceeds 64 KiB; store large payloads as evidence objects")
        return value

    @field_validator("severity", "control_name", "category", "recommendation", "source_tool", mode="before")
    @classmethod
    def _empty_is_none(cls, value: Any) -> Any:
        return None if value == "" else value


@dataclass
class ParseResult:
    rows: list[ImportRow] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    total: int = 0
    source_tool: str | None = None

    def add_error(self, index: int, message: str) -> None:
        if len(self.errors) < MAX_REPORTED_ERRORS:
            self.errors.append({"row": index, "error": message[:500]})


class ImportFormatError(ValueError):
    """The file as a whole cannot be parsed (as opposed to individual invalid rows)."""


def _validate(records: list[Any], result: ParseResult, max_rows: int) -> ParseResult:
    if len(records) > max_rows:
        raise ImportFormatError(f"import has {len(records)} rows; the limit is {max_rows}")
    result.total = len(records)
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            result.add_error(index, "row is not an object")
            continue
        try:
            row = ImportRow.model_validate(record)
        except (ValidationError, ValueError) as exc:
            errors = exc.errors() if isinstance(exc, ValidationError) else [{"loc": (), "msg": str(exc)}]
            result.add_error(index, "; ".join(f"{'.'.join(map(str, e['loc'])) or 'row'}: {e['msg']}"
                                              for e in errors))
            continue
        if row.source_tool is None:
            row.source_tool = result.source_tool
        result.rows.append(row)
    return result


def parse_import(source_type: SourceType, data: bytes, max_rows: int) -> ParseResult:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportFormatError("file is not valid UTF-8") from exc

    if source_type == "eeap_json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ImportFormatError(f"invalid JSON: {exc.msg} at line {exc.lineno}") from exc
        result = ParseResult()
        if isinstance(document, dict):
            result.source_tool = document.get("source_tool")
            document = document.get("findings")
        if not isinstance(document, list):
            raise ImportFormatError('expected a JSON array of findings or {"findings": [...]}')
        return _validate(document, result, max_rows)

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {"asset_id", "control_id", "status"} <= set(reader.fieldnames):
        raise ImportFormatError("CSV header must include asset_id, control_id and status")
    return _validate(list(reader), ParseResult(), max_rows)


def fingerprint(asset_id: str, control_id: str, subject_key: str) -> str:
    return hashlib.sha256(f"{asset_id}|{control_id}|{subject_key}".encode()).hexdigest()


def lifecycle_after_observation(previous: str | None, status: str) -> str:
    """Lifecycle state after a collector/import observes `status` for a finding."""
    if status == "PASS":
        return "resolved"
    if previous is None:
        return "open"
    if status in ("FAIL", "WARNING") and previous == "resolved":
        return "open"  # regression: the weakness came back
    return previous  # human decisions (accepted risk, false positive, triage) persist


def check_triage_transition(current: str, target: str) -> None:
    if target == "risk_accepted":
        raise ValueError("use the risk-acceptance endpoint to accept risk")
    if target == "resolved":
        raise ValueError("findings are resolved when a reassessment or import observes PASS")
    if target not in TRIAGE_TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"cannot move a finding from {current} to {target}")
