"""Pydantic data models shared across all Castellan modules.

These models are the contract between the categorization, catalog, scanner,
mapping, and reporting components (SPEC.md section 9).
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

Impact = Literal["low", "moderate", "high"]
ControlStatus = Literal[
    "implemented", "partial", "not_implemented", "not_assessed", "not_applicable"
]
CheckOutcome = Literal["pass", "fail", "error", "not_applicable"]


class InformationType(BaseModel):
    """One kind of information the system processes, with its CIA impact ratings."""

    name: str
    confidentiality: Impact
    integrity: Impact
    availability: Impact


class SystemDescription(BaseModel):
    """Plain-language description of an information system, parsed from YAML.

    CIA impact levels may be stated directly, or derived from
    ``information_types`` (which take precedence when present); at least one
    of the two must be provided.
    """

    name: str
    system_id: str
    description: str
    owner: str
    information_types: list[InformationType] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    confidentiality: Impact | None = None
    integrity: Impact | None = None
    availability: Impact | None = None

    @model_validator(mode="after")
    def _require_impact_source(self) -> SystemDescription:
        direct = (self.confidentiality, self.integrity, self.availability)
        if not self.information_types and any(value is None for value in direct):
            raise ValueError(
                "provide either a non-empty 'information_types' list or all three of "
                "'confidentiality', 'integrity', and 'availability'"
            )
        return self


class Categorization(BaseModel):
    """FIPS-199 security categorization and the resulting 800-53B baseline."""

    confidentiality: Impact
    integrity: Impact
    availability: Impact
    overall: Impact
    selected_baseline: Impact


class Control(BaseModel):
    """A single SP 800-53 control parsed from the OSCAL catalog."""

    id: str
    family: str
    title: str
    statement: str
    in_baseline: bool


class CheckResult(BaseModel):
    """Outcome of one scanner check against the host."""

    check_id: str
    title: str
    outcome: CheckOutcome
    detail: str
    evidence: str | None = None
    remediation: str


class ControlAssessment(BaseModel):
    """A control joined with the technical check results that map to it."""

    control: Control
    mapped_checks: list[CheckResult] = Field(default_factory=list)
    status: ControlStatus


class POAMItem(BaseModel):
    """One Plan of Action & Milestones entry for a failed or partial control."""

    control_id: str
    weakness: str
    source_check: str
    remediation: str
    status: Literal["open"] = "open"


def load_system_description(path: Path) -> SystemDescription:
    """Parse a system description YAML file into a validated model."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")
    return SystemDescription.model_validate(data)
