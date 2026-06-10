"""Load the cached OSCAL 800-53 catalog and resolve a baseline to controls.

The catalog nests controls inside family groups (and enhancements inside
controls). A baseline profile lists the in-scope control ids under
``imports[].include-controls[].with-ids``; resolving a baseline means
filtering parsed catalog controls against that id set.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from castellan.fetch import CATALOG_FILENAME, DEFAULT_DATA_DIR, PROFILE_FILENAMES
from castellan.models import Control, Impact

_PARAM_INSERT_RE = re.compile(r"\{\{\s*insert:\s*param,\s*(\S+?)\s*\}\}")
_CONTROL_ID_RE = re.compile(r"^([a-z]{2})-(\d+)(?:\.(\d+))?$")

# The 20 SP 800-53 rev5 control families.
FAMILY_TITLES: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "Personally Identifiable Information Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


def format_control_id(control_id: str) -> str:
    """Render a control id in standard notation: ``ac-2`` -> ``AC-2``, ``ac-2.1`` -> ``AC-2(1)``."""
    match = _CONTROL_ID_RE.match(control_id)
    if match is None:
        return control_id.upper()
    base = f"{match.group(1).upper()}-{match.group(2)}"
    return f"{base}({match.group(3)})" if match.group(3) else base


def _param_placeholder(param: dict[str, Any]) -> str:
    """Render an OSCAL parameter as assessor-style bracketed text."""
    if "label" in param:
        return f"[Assignment: organization-defined {param['label']}]"
    select = param.get("select")
    if isinstance(select, dict):
        choices = "; ".join(select.get("choice", []))
        how_many = select.get("how-many")
        qualifier = f" ({how_many})" if how_many else ""
        return f"[Selection{qualifier}: {choices}]"
    return f"[{param.get('id', 'parameter')}]"


def _substitute_params(prose: str, params: dict[str, dict[str, Any]]) -> str:
    def replace(match: re.Match[str]) -> str:
        param = params.get(match.group(1))
        return _param_placeholder(param) if param else f"[{match.group(1)}]"

    # Selection choices may themselves contain inserts; one extra pass covers them.
    once = _PARAM_INSERT_RE.sub(replace, prose)
    return _PARAM_INSERT_RE.sub(replace, once)


def _part_label(part: dict[str, Any]) -> str | None:
    for prop in part.get("props", []):
        if prop.get("name") == "label":
            return str(prop["value"])
    return None


def _flatten_statement(part: dict[str, Any], params: dict[str, dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    prose = part.get("prose")
    if prose:
        label = _part_label(part)
        text = _substitute_params(prose, params)
        lines.append(f"{label} {text}" if label else text)
    for sub in part.get("parts", []):
        lines.extend(_flatten_statement(sub, params))
    return lines


def _statement_text(control: dict[str, Any], params: dict[str, dict[str, Any]]) -> str:
    for part in control.get("parts", []):
        if part.get("name") == "statement":
            return "\n".join(_flatten_statement(part, params))
    return ""


def _parse_control_tree(
    data: dict[str, Any], inherited_params: dict[str, dict[str, Any]]
) -> list[Control]:
    """Parse one catalog control plus its nested enhancements."""
    params = dict(inherited_params)
    for param in data.get("params", []):
        params[param["id"]] = param

    control_id = str(data["id"])
    controls = [
        Control(
            id=control_id,
            family=control_id.split("-", 1)[0].upper(),
            title=str(data["title"]),
            statement=_statement_text(data, params),
            in_baseline=False,
        )
    ]
    for enhancement in data.get("controls", []):
        controls.extend(_parse_control_tree(enhancement, params))
    return controls


def _control_sort_key(control: Control) -> tuple[str, int, int]:
    match = _CONTROL_ID_RE.match(control.id)
    if match is None:
        return (control.family, 0, 0)
    return (match.group(1), int(match.group(2)), int(match.group(3) or 0))


def load_catalog_controls(catalog_path: Path) -> list[Control]:
    """Parse every control (including enhancements) from an OSCAL catalog file."""
    document = json.loads(catalog_path.read_text(encoding="utf-8"))
    controls: list[Control] = []
    for group in document["catalog"]["groups"]:
        for control in group.get("controls", []):
            controls.extend(_parse_control_tree(control, {}))
    return controls


def load_baseline_ids(profile_path: Path) -> set[str]:
    """Collect the control ids a baseline profile includes."""
    document = json.loads(profile_path.read_text(encoding="utf-8"))
    ids: set[str] = set()
    for imported in document["profile"]["imports"]:
        for include in imported.get("include-controls", []):
            ids.update(include.get("with-ids", []))
    return ids


def load_controls(baseline: Impact, data_dir: Path = DEFAULT_DATA_DIR) -> list[Control]:
    """Return the controls in the given 800-53B baseline, sorted by family then id."""
    catalog_path = data_dir / CATALOG_FILENAME
    profile_path = data_dir / PROFILE_FILENAMES[baseline]
    for path in (catalog_path, profile_path):
        if not path.exists():
            raise FileNotFoundError(
                f"OSCAL content not found at {path} — run 'castellan fetch' first"
            )

    baseline_ids = load_baseline_ids(profile_path)
    selected = [
        control.model_copy(update={"in_baseline": True})
        for control in load_catalog_controls(catalog_path)
        if control.id in baseline_ids
    ]
    return sorted(selected, key=_control_sort_key)
