"""Build a System Security Plan from a categorized system and its baseline.

Renders two artifacts:

- ``ssp.md`` — a human-readable SSP skeleton (cover section, FIPS-199
  categorization, then one section per control family with an implementation
  status block per control).
- ``ssp.json`` — an OSCAL ``system-security-plan`` document. The shape mirrors
  the example SSP in ``usnistgov/oscal-content`` (``examples/ssp/json/``):
  ``system-characteristics`` carries the FIPS-199 categorization using
  ``fips-199-<level>`` values, and ``control-implementation`` holds one
  ``implemented-requirements`` entry per in-baseline control with an
  ``implementation-status`` property. It aims for structural fidelity, not
  full schema validation (see SPEC.md section 10.5).

UUIDs are deterministic (UUIDv5 seeded from the system id) so regenerating an
SSP for the same system yields stable identifiers.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from castellan.catalog import FAMILY_TITLES, format_control_id
from castellan.fetch import PROFILE_FILENAMES
from castellan.models import Categorization, Control, ControlStatus, SystemDescription

OSCAL_VERSION = "1.1.2"

_UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/castellan")

_PROFILE_BASE_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json"
)


def _stable_uuid(*parts: str) -> str:
    return str(uuid.uuid5(_UUID_NAMESPACE, "/".join(parts)))


def _status_for(control: Control, statuses: Mapping[str, ControlStatus]) -> ControlStatus:
    return statuses.get(control.id, "not_assessed")


def _group_by_family(controls: list[Control]) -> list[dict[str, Any]]:
    """Group baseline controls into ordered per-family sections for the template."""
    families: dict[str, list[Control]] = {}
    for control in controls:
        families.setdefault(control.family, []).append(control)
    return [
        {
            "code": family,
            "title": FAMILY_TITLES.get(family, family),
            "controls": members,
        }
        for family, members in sorted(families.items())
    ]


def render_ssp_markdown(
    system: SystemDescription,
    categorization: Categorization,
    controls: list[Control],
    statuses: Mapping[str, ControlStatus] | None = None,
) -> str:
    """Render the human-readable SSP skeleton."""
    statuses = statuses or {}
    env = Environment(
        loader=PackageLoader("castellan", "templates"),
        autoescape=select_autoescape(default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["control_id"] = format_control_id
    template = env.get_template("ssp.md.j2")
    return template.render(
        system=system,
        cat=categorization,
        families=_group_by_family(controls),
        control_count=len(controls),
        statuses={c.id: _status_for(c, statuses) for c in controls},
        generated=datetime.now(UTC).strftime("%Y-%m-%d"),
    )


def _information_types(system: SystemDescription) -> list[dict[str, Any]]:
    return [
        {
            "uuid": _stable_uuid(system.system_id, "info-type", info.name),
            "title": info.name,
            "description": info.name,
            "confidentiality-impact": {"base": f"fips-199-{info.confidentiality}"},
            "integrity-impact": {"base": f"fips-199-{info.integrity}"},
            "availability-impact": {"base": f"fips-199-{info.availability}"},
        }
        for info in system.information_types
    ]


def _components(system: SystemDescription) -> list[dict[str, Any]]:
    this_system = {
        "uuid": _stable_uuid(system.system_id, "component", "this-system"),
        "type": "this-system",
        "title": system.name,
        "description": system.description.strip(),
        "status": {"state": "operational"},
    }
    parts = [
        {
            "uuid": _stable_uuid(system.system_id, "component", text),
            "type": "software",
            "title": text,
            "description": text,
            "status": {"state": "operational"},
        }
        for text in system.components
    ]
    return [this_system, *parts]


def build_oscal_ssp(
    system: SystemDescription,
    categorization: Categorization,
    controls: list[Control],
    statuses: Mapping[str, ControlStatus] | None = None,
) -> dict[str, Any]:
    """Build an OSCAL ``system-security-plan`` document as a plain dict."""
    statuses = statuses or {}
    implemented_requirements = [
        {
            "uuid": _stable_uuid(system.system_id, "impl-req", control.id),
            "control-id": control.id,
            "props": [
                {
                    "name": "implementation-status",
                    "value": _status_for(control, statuses).replace("_", "-"),
                }
            ],
            "remarks": (
                f"{format_control_id(control.id)} ({control.title}) — implementation "
                "narrative to be completed by the system owner."
            ),
        }
        for control in controls
    ]
    return {
        "system-security-plan": {
            "uuid": _stable_uuid(system.system_id, "ssp"),
            "metadata": {
                "title": f"System Security Plan: {system.name}",
                "last-modified": datetime.now(UTC).isoformat(),
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
                "roles": [{"id": "system-owner", "title": "System Owner"}],
            },
            "import-profile": {
                "href": f"{_PROFILE_BASE_URL}/{PROFILE_FILENAMES[categorization.selected_baseline]}"
            },
            "system-characteristics": {
                "system-ids": [{"id": system.system_id}],
                "system-name": system.name,
                "description": system.description.strip(),
                "security-sensitivity-level": f"fips-199-{categorization.overall}",
                "system-information": {"information-types": _information_types(system)},
                "security-impact-level": {
                    "security-objective-confidentiality": (
                        f"fips-199-{categorization.confidentiality}"
                    ),
                    "security-objective-integrity": f"fips-199-{categorization.integrity}",
                    "security-objective-availability": f"fips-199-{categorization.availability}",
                },
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": "All components listed in the system implementation."
                },
            },
            "system-implementation": {
                "users": [
                    {
                        "uuid": _stable_uuid(system.system_id, "user", system.owner),
                        "title": system.owner,
                        "role-ids": ["system-owner"],
                    }
                ],
                "components": _components(system),
            },
            "control-implementation": {
                "description": (
                    f"Implemented requirements for the SP 800-53B "
                    f"{categorization.selected_baseline} baseline ({len(controls)} controls)."
                ),
                "implemented-requirements": implemented_requirements,
            },
        }
    }


def write_ssp(
    system: SystemDescription,
    categorization: Categorization,
    controls: list[Control],
    out_dir: Path,
    statuses: Mapping[str, ControlStatus] | None = None,
) -> tuple[Path, Path]:
    """Write ``ssp.md`` and ``ssp.json`` into *out_dir*; returns their paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "ssp.md"
    json_path = out_dir / "ssp.json"
    md_path.write_text(
        render_ssp_markdown(system, categorization, controls, statuses),
        encoding="utf-8",
        newline="\n",
    )
    json_path.write_text(
        json.dumps(build_oscal_ssp(system, categorization, controls, statuses), indent=2),
        encoding="utf-8",
        newline="\n",
    )
    return md_path, json_path
