"""Tests for the check->control mapping and control status computation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest

from castellan.catalog import load_baseline_ids, load_catalog_controls
from castellan.fetch import CATALOG_FILENAME, DEFAULT_DATA_DIR, PROFILE_FILENAMES
from castellan.mapping import (
    DEFAULT_MAPPING_PATH,
    assess,
    compute_status,
    load_check_control_map,
)
from castellan.models import CheckOutcome, CheckResult, Control
from castellan.scanner.runner import ALL_CHECKS

CONTROL_ID_RE = re.compile(r"^[a-z]{2}-\d+(\.\d+)?$")


def make_result(check_id: str, outcome: CheckOutcome) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        title=f"title {check_id}",
        outcome=outcome,
        detail=f"detail {check_id}",
        remediation=f"remediation {check_id}",
    )


def make_control(control_id: str) -> Control:
    return Control(
        id=control_id,
        family=control_id.split("-")[0].upper(),
        title=f"Control {control_id}",
        statement="statement",
        in_baseline=True,
    )


class TestComputeStatus:
    @pytest.mark.parametrize(
        ("outcomes", "expected"),
        [
            (["pass"], "implemented"),
            (["pass", "pass"], "implemented"),
            (["pass", "fail"], "partial"),
            (["fail"], "not_implemented"),
            (["fail", "fail"], "not_implemented"),
            ([], "not_assessed"),
            (["not_applicable"], "not_assessed"),
            (["error"], "not_assessed"),
            (["not_applicable", "error"], "not_assessed"),
            # evidence-free outcomes are excluded, not counted as failures
            (["pass", "not_applicable"], "implemented"),
            (["pass", "error"], "implemented"),
            (["fail", "not_applicable"], "not_implemented"),
            (["pass", "fail", "error", "not_applicable"], "partial"),
        ],
    )
    def test_status_rules(self, outcomes: list[CheckOutcome], expected: str) -> None:
        checks = [make_result(f"check_{i}", outcome) for i, outcome in enumerate(outcomes)]
        assert compute_status(checks) == expected


class TestLoadMapping:
    def test_loads_curated_file(self) -> None:
        mapping = load_check_control_map()
        assert len(mapping) == len(ALL_CHECKS)

    def test_every_implemented_check_is_mapped(self) -> None:
        mapping = load_check_control_map()
        unmapped = [c.check_id for c in ALL_CHECKS if c.check_id not in mapping]
        assert unmapped == []

    def test_no_stale_entries_for_removed_checks(self) -> None:
        mapping = load_check_control_map()
        known = {c.check_id for c in ALL_CHECKS}
        stale = [check_id for check_id in mapping if check_id not in known]
        assert stale == []

    def test_all_control_ids_are_well_formed(self) -> None:
        mapping = load_check_control_map()
        for check_id, control_ids in mapping.items():
            for control_id in control_ids:
                assert CONTROL_ID_RE.match(control_id), f"{check_id} -> {control_id}"

    def test_rejects_non_mapping_yaml(self, tmp_path: Path) -> None:
        bad = tmp_path / "map.yaml"
        bad.write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(ValueError, match="expected a YAML mapping"):
            load_check_control_map(bad)

    def test_rejects_empty_control_list(self, tmp_path: Path) -> None:
        bad = tmp_path / "map.yaml"
        bad.write_text("some_check: []\n", encoding="utf-8")
        with pytest.raises(ValueError, match="maps to no controls"):
            load_check_control_map(bad)

    def test_rejects_non_list_value(self, tmp_path: Path) -> None:
        bad = tmp_path / "map.yaml"
        bad.write_text("some_check: ac-2\n", encoding="utf-8")
        with pytest.raises(ValueError, match="must map to a list"):
            load_check_control_map(bad)


class TestAssess:
    MAPPING: ClassVar[dict[str, list[str]]] = {
        "check_a": ["ac-1", "ac-2"],
        "check_b": ["ac-2"],
        "check_stale": ["sc-7"],
    }

    def test_joins_results_to_controls(self) -> None:
        controls = [make_control("ac-1"), make_control("ac-2"), make_control("au-9")]
        results = [make_result("check_a", "pass"), make_result("check_b", "fail")]
        assessments = {a.control.id: a for a in assess(controls, results, self.MAPPING)}

        assert [c.check_id for c in assessments["ac-1"].mapped_checks] == ["check_a"]
        assert assessments["ac-1"].status == "implemented"
        assert {c.check_id for c in assessments["ac-2"].mapped_checks} == {
            "check_a",
            "check_b",
        }
        assert assessments["ac-2"].status == "partial"

    def test_unmapped_control_is_not_assessed(self) -> None:
        controls = [make_control("au-9")]
        results = [make_result("check_a", "pass")]
        (assessment,) = assess(controls, results, self.MAPPING)
        assert assessment.status == "not_assessed"
        assert assessment.mapped_checks == []

    def test_mapping_entry_without_result_is_ignored(self) -> None:
        # check_stale maps to sc-7 but produced no result; sc-7 stays unassessed.
        controls = [make_control("sc-7")]
        results = [make_result("check_a", "pass")]
        (assessment,) = assess(controls, results, self.MAPPING)
        assert assessment.status == "not_assessed"

    def test_one_assessment_per_control_in_order(self) -> None:
        controls = [make_control("ac-1"), make_control("ac-2")]
        assessments = assess(controls, [], self.MAPPING)
        assert [a.control.id for a in assessments] == ["ac-1", "ac-2"]

    def test_default_mapping_is_loaded_when_omitted(self) -> None:
        controls = [make_control("ac-6")]
        results = [make_result("ssh_permit_root_login", "fail")]
        (assessment,) = assess(controls, results)
        assert assessment.status == "not_implemented"


@pytest.mark.skipif(
    not (DEFAULT_DATA_DIR / CATALOG_FILENAME).exists(),
    reason="real OSCAL content not fetched (run 'castellan fetch')",
)
class TestMappingAgainstRealCatalog:
    def test_every_mapped_control_exists_in_catalog(self) -> None:
        catalog_ids = {c.id for c in load_catalog_controls(DEFAULT_DATA_DIR / CATALOG_FILENAME)}
        for check_id, control_ids in load_check_control_map().items():
            missing = [c for c in control_ids if c not in catalog_ids]
            assert not missing, f"{check_id} maps to unknown control(s): {missing}"

    def test_every_mapped_control_is_in_moderate_baseline(self) -> None:
        moderate = load_baseline_ids(DEFAULT_DATA_DIR / PROFILE_FILENAMES["moderate"])
        for check_id, control_ids in load_check_control_map().items():
            outside = [c for c in control_ids if c not in moderate]
            assert not outside, f"{check_id} maps outside the moderate baseline: {outside}"

    def test_mapping_file_is_the_committed_one(self) -> None:
        assert DEFAULT_MAPPING_PATH.exists()
