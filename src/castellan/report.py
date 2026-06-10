"""Compliance report, POA&M, and OSCAL assessment-results generation.

Combines the control assessments (mapping.py) into the final evidence
package:

- ``compliance_report.md`` — executive summary, per-family rollup, and a
  detail section per technically-assessed control with check evidence.
- ``poam.md`` / ``poam.json`` — one POA&M item per failed or partial control;
  the JSON follows the OSCAL ``plan-of-action-and-milestones`` shape.
- ``assessment_results.json`` — OSCAL ``assessment-results`` shape: one
  observation per executed check, one finding per technically-assessed
  control (satisfied / not-satisfied).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from castellan.catalog import FAMILY_TITLES, format_control_id
from castellan.models import (
    Categorization,
    CheckResult,
    ControlAssessment,
    ControlStatus,
    POAMItem,
    SystemDescription,
)
from castellan.ssp import OSCAL_VERSION, stable_uuid
from castellan.templating import jinja_env

_STATUS_ORDER: tuple[ControlStatus, ...] = (
    "implemented",
    "partial",
    "not_implemented",
    "not_assessed",
    "not_applicable",
)


class ReportSummary(BaseModel):
    """Counts used by the executive summary."""

    total: int
    counts: dict[ControlStatus, int]
    assessable: int
    passing_pct: float | None


def summarize(assessments: list[ControlAssessment]) -> ReportSummary:
    """Roll assessment statuses up into executive-summary numbers."""
    counts: dict[ControlStatus, int] = dict.fromkeys(_STATUS_ORDER, 0)
    for assessment in assessments:
        counts[assessment.status] += 1
    assessable = counts["implemented"] + counts["partial"] + counts["not_implemented"]
    passing_pct = round(100 * counts["implemented"] / assessable, 1) if assessable else None
    return ReportSummary(
        total=len(assessments),
        counts=counts,
        assessable=assessable,
        passing_pct=passing_pct,
    )


def family_rollup(assessments: list[ControlAssessment]) -> list[dict[str, Any]]:
    """Per-family status counts, sorted by family code."""
    families: dict[str, dict[ControlStatus, int]] = {}
    for assessment in assessments:
        family = assessment.control.family
        counts = families.setdefault(family, dict.fromkeys(_STATUS_ORDER, 0))
        counts[assessment.status] += 1
    return [
        {
            "code": family,
            "title": FAMILY_TITLES.get(family, family),
            "counts": counts,
            "total": sum(counts.values()),
        }
        for family, counts in sorted(families.items())
    ]


def build_poam_items(assessments: list[ControlAssessment]) -> list[POAMItem]:
    """One open POA&M item per failed or partial control."""
    items: list[POAMItem] = []
    for assessment in assessments:
        if assessment.status not in ("partial", "not_implemented"):
            continue
        failing = [c for c in assessment.mapped_checks if c.outcome == "fail"]
        control_label = format_control_id(assessment.control.id)
        weakness = (
            f"{control_label} ({assessment.control.title}) is {assessment.status} — "
            f"failing: {'; '.join(c.detail for c in failing)}"
        )
        items.append(
            POAMItem(
                control_id=assessment.control.id,
                weakness=weakness,
                source_check=", ".join(c.check_id for c in failing),
                remediation=" ".join(dict.fromkeys(c.remediation for c in failing)),
            )
        )
    return items


def render_report_markdown(
    system: SystemDescription,
    categorization: Categorization,
    assessments: list[ControlAssessment],
) -> str:
    """Render the human-readable compliance report."""
    assessed = [a for a in assessments if a.mapped_checks]
    template = jinja_env().get_template("report.md.j2")
    return template.render(
        system=system,
        cat=categorization,
        summary=summarize(assessments),
        families=family_rollup(assessments),
        assessed=assessed,
        poam_items=build_poam_items(assessments),
        generated=datetime.now(UTC).strftime("%Y-%m-%d"),
    )


def render_poam_markdown(system: SystemDescription, items: list[POAMItem]) -> str:
    """Render the human-readable POA&M."""
    template = jinja_env().get_template("poam.md.j2")
    return template.render(
        system=system,
        items=items,
        generated=datetime.now(UTC).strftime("%Y-%m-%d"),
    )


def build_oscal_poam(system: SystemDescription, items: list[POAMItem]) -> dict[str, Any]:
    """Build an OSCAL ``plan-of-action-and-milestones`` document."""
    return {
        "plan-of-action-and-milestones": {
            "uuid": stable_uuid(system.system_id, "poam"),
            "metadata": {
                "title": f"Plan of Action and Milestones: {system.name}",
                "last-modified": datetime.now(UTC).isoformat(),
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
            },
            "system-id": {"id": system.system_id},
            "poam-items": [
                {
                    "uuid": stable_uuid(system.system_id, "poam-item", item.control_id),
                    "title": (
                        f"{format_control_id(item.control_id)}: remediate failed "
                        "hardening checks"
                    ),
                    "description": item.weakness,
                    "props": [
                        {"name": "status", "value": item.status},
                        {"name": "source-check", "value": item.source_check},
                    ],
                    "remarks": item.remediation,
                }
                for item in items
            ],
        }
    }


def _finding_state(status: ControlStatus) -> str:
    return "satisfied" if status == "implemented" else "not-satisfied"


def build_oscal_assessment_results(
    system: SystemDescription,
    results: list[CheckResult],
    assessments: list[ControlAssessment],
) -> dict[str, Any]:
    """Build an OSCAL ``assessment-results`` document.

    Each executed check becomes an observation; each control with mapped
    check evidence becomes a finding targeting that control.
    """
    now = datetime.now(UTC).isoformat()
    observations = [
        {
            "uuid": stable_uuid(system.system_id, "observation", result.check_id),
            "title": result.title,
            "description": f"[{result.check_id}] outcome={result.outcome}: {result.detail}",
            "methods": ["TEST"],
            "collected": now,
            **(
                {"relevant-evidence": [{"description": result.evidence}]}
                if result.evidence
                else {}
            ),
        }
        for result in results
    ]
    assessed = [a for a in assessments if a.status != "not_assessed"]
    findings = [
        {
            "uuid": stable_uuid(system.system_id, "finding", assessment.control.id),
            "title": (
                f"{format_control_id(assessment.control.id)} — {assessment.control.title}"
            ),
            "description": (
                f"Status {assessment.status} based on "
                f"{len(assessment.mapped_checks)} mapped check(s)."
            ),
            "target": {
                "type": "objective-id",
                "target-id": assessment.control.id,
                "status": {"state": _finding_state(assessment.status)},
            },
            "related-observations": [
                {"observation-uuid": stable_uuid(system.system_id, "observation", c.check_id)}
                for c in assessment.mapped_checks
            ],
        }
        for assessment in assessed
    ]
    return {
        "assessment-results": {
            "uuid": stable_uuid(system.system_id, "assessment-results"),
            "metadata": {
                "title": f"Assessment Results: {system.name}",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
            },
            "import-ap": {"href": "#castellan-automated-scan"},
            "results": [
                {
                    "uuid": stable_uuid(system.system_id, "result", "host-scan"),
                    "title": "Castellan automated host scan",
                    "description": (
                        "Read-only CIS/STIG-style hardening checks mapped to SP 800-53 "
                        "controls via data/mappings/check_control_map.yaml."
                    ),
                    "start": now,
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "include-controls": [
                                    {"control-id": a.control.id} for a in assessed
                                ]
                            }
                        ]
                    },
                    "observations": observations,
                    "findings": findings,
                }
            ],
        }
    }


def write_report_artifacts(
    system: SystemDescription,
    categorization: Categorization,
    assessments: list[ControlAssessment],
    results: list[CheckResult],
    out_dir: Path,
) -> dict[str, Path]:
    """Write the report artifact set; returns name -> path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    items = build_poam_items(assessments)
    artifacts = {
        "compliance_report.md": render_report_markdown(system, categorization, assessments),
        "poam.md": render_poam_markdown(system, items),
        "poam.json": json.dumps(build_oscal_poam(system, items), indent=2) + "\n",
        "assessment_results.json": (
            json.dumps(build_oscal_assessment_results(system, results, assessments), indent=2)
            + "\n"
        ),
    }
    paths: dict[str, Path] = {}
    for name, content in artifacts.items():
        path = out_dir / name
        path.write_text(content, encoding="utf-8", newline="\n")
        paths[name] = path
    return paths
