"""Join scanner findings to 800-53 controls — the heart of the tool.

Status rules (SPEC.md section 9), applied to each in-baseline control:

- every mapped check passes      -> ``implemented``
- some pass, some fail           -> ``partial``
- every mapped check fails       -> ``not_implemented``
- no mapped checks               -> ``not_assessed``

Checks that came back ``not_applicable`` or ``error`` carry no evidence
either way, so they are excluded from the pass/fail computation; a control
whose mapped checks all came back evidence-free is ``not_assessed``. Controls
are never auto-passed: most 800-53 controls are organizational and a host
scan honestly cannot assess them.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from castellan.models import CheckResult, Control, ControlAssessment, ControlStatus

DEFAULT_MAPPING_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "mappings" / "check_control_map.yaml"
)


def load_check_control_map(path: Path = DEFAULT_MAPPING_PATH) -> dict[str, list[str]]:
    """Load the curated check_id -> [control_id, ...] mapping."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping of check_id -> [control ids]")
    mapping: dict[str, list[str]] = {}
    for check_id, control_ids in data.items():
        if not isinstance(control_ids, list) or not all(
            isinstance(c, str) for c in control_ids
        ):
            raise ValueError(f"{path}: '{check_id}' must map to a list of control id strings")
        if not control_ids:
            raise ValueError(f"{path}: '{check_id}' maps to no controls")
        mapping[str(check_id)] = [str(c) for c in control_ids]
    return mapping


def compute_status(mapped_checks: list[CheckResult]) -> ControlStatus:
    """Derive a control's status from its mapped check results."""
    outcomes = {result.outcome for result in mapped_checks}
    assessable = outcomes & {"pass", "fail"}
    if not assessable:
        return "not_assessed"
    if assessable == {"pass"}:
        return "implemented"
    if assessable == {"fail"}:
        return "not_implemented"
    return "partial"


def assess(
    controls: list[Control],
    results: list[CheckResult],
    mapping: dict[str, list[str]] | None = None,
) -> list[ControlAssessment]:
    """Attach mapped check results to each control and compute its status."""
    if mapping is None:
        mapping = load_check_control_map()
    checks_by_control: dict[str, list[CheckResult]] = {}
    results_by_id = {result.check_id: result for result in results}
    for check_id, control_ids in mapping.items():
        result = results_by_id.get(check_id)
        if result is None:
            continue
        for control_id in control_ids:
            checks_by_control.setdefault(control_id, []).append(result)
    return [
        ControlAssessment(
            control=control,
            mapped_checks=checks_by_control.get(control.id, []),
            status=compute_status(checks_by_control.get(control.id, [])),
        )
        for control in controls
    ]
