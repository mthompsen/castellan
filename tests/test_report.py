"""Tests for the compliance report, POA&M, and OSCAL assessment results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from castellan.categorize import categorize
from castellan.mapping import assess
from castellan.models import (
    Categorization,
    CheckOutcome,
    CheckResult,
    Control,
    ControlAssessment,
    SystemDescription,
)
from castellan.report import (
    build_oscal_assessment_results,
    build_oscal_poam,
    build_poam_items,
    family_rollup,
    render_poam_markdown,
    render_report_markdown,
    summarize,
    write_report_artifacts,
)

MAPPING = {
    "check_pass": ["ac-1"],
    "check_fail": ["ac-2", "au-9"],
    "check_pass2": ["ac-2"],
    "check_na": ["sc-7"],
}


def make_result(check_id: str, outcome: CheckOutcome, evidence: str | None = None) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        title=f"Title of {check_id}",
        outcome=outcome,
        detail=f"detail of {check_id}",
        evidence=evidence,
        remediation=f"Remediate {check_id}.",
    )


def make_control(control_id: str, title: str = "") -> Control:
    return Control(
        id=control_id,
        family=control_id.split("-")[0].upper(),
        title=title or f"Control {control_id}",
        statement="statement",
        in_baseline=True,
    )


@pytest.fixture(scope="module")
def system() -> SystemDescription:
    return SystemDescription(
        name="Fixture System",
        system_id="FS-1",
        description="A system under report test.",
        owner="Fixture Owner",
        confidentiality="moderate",
        integrity="moderate",
        availability="low",
    )


@pytest.fixture(scope="module")
def categorization(system: SystemDescription) -> Categorization:
    return categorize(system)


@pytest.fixture(scope="module")
def results() -> list[CheckResult]:
    return [
        make_result("check_pass", "pass", evidence="PermitRootLogin no"),
        make_result("check_fail", "fail", evidence="PASS_MAX_DAYS 99999"),
        make_result("check_pass2", "pass"),
        make_result("check_na", "not_applicable"),
    ]


@pytest.fixture(scope="module")
def assessments(results: list[CheckResult]) -> list[ControlAssessment]:
    controls = [
        make_control("ac-1"),  # implemented (check_pass)
        make_control("ac-2"),  # partial (check_fail + check_pass2)
        make_control("au-9"),  # not_implemented (check_fail)
        make_control("sc-7"),  # not_assessed (check_na carries no evidence)
        make_control("si-2"),  # not_assessed (nothing mapped)
    ]
    return assess(controls, results, MAPPING)


class TestSummarize:
    def test_counts(self, assessments: list[ControlAssessment]) -> None:
        summary = summarize(assessments)
        assert summary.total == 5
        assert summary.counts["implemented"] == 1
        assert summary.counts["partial"] == 1
        assert summary.counts["not_implemented"] == 1
        assert summary.counts["not_assessed"] == 2

    def test_passing_pct_over_assessable_only(self, assessments: list[ControlAssessment]) -> None:
        summary = summarize(assessments)
        assert summary.assessable == 3
        assert summary.passing_pct == pytest.approx(33.3)

    def test_pct_none_when_nothing_assessable(self) -> None:
        assessments = assess([make_control("si-2")], [], {})
        assert summarize(assessments).passing_pct is None


class TestFamilyRollup:
    def test_rollup_counts_and_order(self, assessments: list[ControlAssessment]) -> None:
        rollup = family_rollup(assessments)
        assert [f["code"] for f in rollup] == ["AC", "AU", "SC", "SI"]
        ac = rollup[0]
        assert ac["title"] == "Access Control"
        assert ac["counts"]["implemented"] == 1
        assert ac["counts"]["partial"] == 1
        assert ac["total"] == 2


class TestPoamItems:
    def test_one_item_per_failed_or_partial_control(
        self, assessments: list[ControlAssessment]
    ) -> None:
        items = build_poam_items(assessments)
        assert [i.control_id for i in items] == ["ac-2", "au-9"]
        assert all(i.status == "open" for i in items)

    def test_item_carries_failing_check_and_remediation(
        self, assessments: list[ControlAssessment]
    ) -> None:
        items = {i.control_id: i for i in build_poam_items(assessments)}
        assert items["ac-2"].source_check == "check_fail"
        assert "Remediate check_fail." in items["ac-2"].remediation
        assert "partial" in items["ac-2"].weakness
        assert "detail of check_fail" in items["au-9"].weakness


class TestMarkdownRendering:
    def test_report_contains_summary_and_families(
        self,
        system: SystemDescription,
        categorization: Categorization,
        assessments: list[ControlAssessment],
    ) -> None:
        rendered = render_report_markdown(system, categorization, assessments)
        assert "# Compliance Report: Fixture System" in rendered
        assert "| Implemented | 1 |" in rendered
        assert "**33.3%**" in rendered
        assert "| AC | Access Control | 1 | 1 | 0 | 0 | 2 |" in rendered

    def test_report_details_assessed_controls_with_evidence(
        self,
        system: SystemDescription,
        categorization: Categorization,
        assessments: list[ControlAssessment],
    ) -> None:
        rendered = render_report_markdown(system, categorization, assessments)
        assert "### AC-1 — Control ac-1: implemented" in rendered
        assert "### AU-9 — Control au-9: not implemented" in rendered
        assert "`PermitRootLogin no`" in rendered
        # si-2 has no mapped checks: no detail section.
        assert "### SI-2" not in rendered

    def test_poam_markdown(self, system: SystemDescription,
                           assessments: list[ControlAssessment]) -> None:
        rendered = render_poam_markdown(system, build_poam_items(assessments))
        assert "## POAM-1: AC-2" in rendered
        assert "## POAM-2: AU-9" in rendered
        assert "**Status:** open" in rendered

    def test_poam_markdown_with_no_items(self, system: SystemDescription) -> None:
        rendered = render_poam_markdown(system, [])
        assert "No open POA&M items" in rendered


class TestOscalPoam:
    def test_shape_and_items(
        self, system: SystemDescription, assessments: list[ControlAssessment]
    ) -> None:
        document = build_oscal_poam(system, build_poam_items(assessments))
        poam = document["plan-of-action-and-milestones"]
        assert poam["uuid"]
        assert poam["metadata"]["oscal-version"]
        assert poam["system-id"] == {"id": "FS-1"}
        items = poam["poam-items"]
        assert len(items) == 2
        assert items[0]["props"][0] == {"name": "status", "value": "open"}
        assert "AC-2" in items[0]["title"]


class TestOscalAssessmentResults:
    @pytest.fixture(scope="class")
    def document(
        self,
        system: SystemDescription,
        results: list[CheckResult],
        assessments: list[ControlAssessment],
    ) -> dict[str, Any]:
        return build_oscal_assessment_results(system, results, assessments)

    def test_one_observation_per_check(
        self, document: dict[str, Any], results: list[CheckResult]
    ) -> None:
        result = document["assessment-results"]["results"][0]
        observations = result["observations"]
        assert len(observations) == len(results)
        assert observations[0]["methods"] == ["TEST"]
        assert "outcome=pass" in observations[0]["description"]

    def test_evidence_attached_when_present(self, document: dict[str, Any]) -> None:
        observations = document["assessment-results"]["results"][0]["observations"]
        by_title = {o["title"]: o for o in observations}
        assert by_title["Title of check_pass"]["relevant-evidence"] == [
            {"description": "PermitRootLogin no"}
        ]
        assert "relevant-evidence" not in by_title["Title of check_pass2"]

    def test_findings_only_for_assessed_controls(self, document: dict[str, Any]) -> None:
        findings = document["assessment-results"]["results"][0]["findings"]
        targets = {f["target"]["target-id"]: f["target"]["status"]["state"] for f in findings}
        assert targets == {
            "ac-1": "satisfied",
            "ac-2": "not-satisfied",
            "au-9": "not-satisfied",
        }

    def test_findings_link_to_observations(self, document: dict[str, Any]) -> None:
        result = document["assessment-results"]["results"][0]
        observation_uuids = {o["uuid"] for o in result["observations"]}
        for finding in result["findings"]:
            for related in finding["related-observations"]:
                assert related["observation-uuid"] in observation_uuids


class TestWriteArtifacts:
    def test_writes_all_four_files(
        self,
        tmp_path: Path,
        system: SystemDescription,
        categorization: Categorization,
        assessments: list[ControlAssessment],
        results: list[CheckResult],
    ) -> None:
        paths = write_report_artifacts(
            system, categorization, assessments, results, tmp_path / "out"
        )
        assert set(paths) == {
            "compliance_report.md",
            "poam.md",
            "poam.json",
            "assessment_results.json",
        }
        for path in paths.values():
            assert path.exists()
        poam = json.loads(paths["poam.json"].read_text(encoding="utf-8"))
        assert "plan-of-action-and-milestones" in poam
        ar = json.loads(paths["assessment_results.json"].read_text(encoding="utf-8"))
        assert "assessment-results" in ar
