"""Tests for SSP rendering (markdown skeleton + OSCAL system-security-plan)."""

import json
from pathlib import Path

import pytest

from castellan.catalog import format_control_id, load_baseline_ids, load_catalog_controls
from castellan.categorize import categorize
from castellan.models import Categorization, Control, ControlStatus, SystemDescription
from castellan.ssp import build_oscal_ssp, render_ssp_markdown, write_ssp

FIXTURES = Path(__file__).parent / "fixtures" / "oscal"


@pytest.fixture(scope="module")
def system() -> SystemDescription:
    return SystemDescription(
        name="Fixture System",
        system_id="FS-1",
        description="A system used in SSP tests.",
        owner="Fixture Owner",
        components=["Ubuntu 22.04 web server", "PostgreSQL 15"],
        information_types=[
            {
                "name": "Records",
                "confidentiality": "moderate",
                "integrity": "moderate",
                "availability": "low",
            }
        ],
    )


@pytest.fixture(scope="module")
def categorization(system: SystemDescription) -> Categorization:
    return categorize(system)


@pytest.fixture(scope="module")
def controls() -> list[Control]:
    baseline_ids = load_baseline_ids(FIXTURES / "mini_profile_moderate.json")
    return [
        c.model_copy(update={"in_baseline": True})
        for c in load_catalog_controls(FIXTURES / "mini_catalog.json")
        if c.id in baseline_ids
    ]


class TestFormatControlId:
    def test_base_control(self) -> None:
        assert format_control_id("ac-2") == "AC-2"

    def test_enhancement_uses_parens(self) -> None:
        assert format_control_id("ac-2.13") == "AC-2(13)"


class TestMarkdownSsp:
    @pytest.fixture(scope="class")
    def rendered(
        self,
        system: SystemDescription,
        categorization: Categorization,
        controls: list[Control],
    ) -> str:
        return render_ssp_markdown(system, categorization, controls)

    def test_cover_section(self, rendered: str) -> None:
        assert "# System Security Plan: Fixture System" in rendered
        assert "| System identifier | FS-1 |" in rendered
        assert "| System owner | Fixture Owner |" in rendered

    def test_categorization_section(self, rendered: str) -> None:
        assert "| Records | moderate | moderate | low |" in rendered
        assert "| Confidentiality | moderate |" in rendered
        assert "**moderate**" in rendered

    def test_components_listed(self, rendered: str) -> None:
        assert "- Ubuntu 22.04 web server" in rendered
        assert "- PostgreSQL 15" in rendered

    def test_family_sections(self, rendered: str) -> None:
        assert "### AC — Access Control" in rendered
        assert "### SC — System and Communications Protection" in rendered

    def test_control_sections_with_statements(self, rendered: str) -> None:
        assert "#### AC-2 — Account Management" in rendered
        assert "#### AC-2(13) — Disable Accounts for High-risk Individuals" in rendered
        assert "> a. Define and document the types of accounts allowed;" in rendered

    def test_every_control_defaults_not_assessed(
        self, rendered: str, controls: list[Control]
    ) -> None:
        assert rendered.count("**Implementation status:** not_assessed") == len(controls)

    def test_statuses_override_default(
        self,
        system: SystemDescription,
        categorization: Categorization,
        controls: list[Control],
    ) -> None:
        statuses: dict[str, ControlStatus] = {"ac-2": "implemented", "sc-7": "partial"}
        rendered = render_ssp_markdown(system, categorization, controls, statuses)
        assert "**Implementation status:** implemented" in rendered
        assert "**Implementation status:** partial" in rendered
        assert rendered.count("**Implementation status:** not_assessed") == len(controls) - 2


class TestOscalSsp:
    @pytest.fixture(scope="class")
    def document(
        self,
        system: SystemDescription,
        categorization: Categorization,
        controls: list[Control],
    ) -> dict[str, object]:
        return build_oscal_ssp(system, categorization, controls)

    @pytest.fixture(scope="class")
    def ssp(self, document: dict[str, object]) -> dict[str, object]:
        body = document["system-security-plan"]
        assert isinstance(body, dict)
        return body

    def test_top_level_shape(self, ssp: dict[str, object]) -> None:
        assert {
            "uuid",
            "metadata",
            "import-profile",
            "system-characteristics",
            "system-implementation",
            "control-implementation",
        } <= set(ssp)

    def test_metadata(self, ssp: dict[str, object]) -> None:
        metadata = ssp["metadata"]
        assert isinstance(metadata, dict)
        assert metadata["title"] == "System Security Plan: Fixture System"
        assert metadata["oscal-version"]
        assert metadata["last-modified"]

    def test_import_profile_points_at_selected_baseline(self, ssp: dict[str, object]) -> None:
        import_profile = ssp["import-profile"]
        assert isinstance(import_profile, dict)
        assert "MODERATE-baseline_profile.json" in str(import_profile["href"])

    def test_security_impact_level_uses_fips199_values(self, ssp: dict[str, object]) -> None:
        characteristics = ssp["system-characteristics"]
        assert isinstance(characteristics, dict)
        assert characteristics["security-sensitivity-level"] == "fips-199-moderate"
        impact = characteristics["security-impact-level"]
        assert isinstance(impact, dict)
        assert impact["security-objective-confidentiality"] == "fips-199-moderate"
        assert impact["security-objective-integrity"] == "fips-199-moderate"
        assert impact["security-objective-availability"] == "fips-199-low"

    def test_information_types(self, ssp: dict[str, object]) -> None:
        characteristics = ssp["system-characteristics"]
        assert isinstance(characteristics, dict)
        info = characteristics["system-information"]
        assert isinstance(info, dict)
        types = info["information-types"]
        assert isinstance(types, list)
        assert len(types) == 1
        assert types[0]["title"] == "Records"
        assert types[0]["confidentiality-impact"] == {"base": "fips-199-moderate"}

    def test_components_include_this_system(self, ssp: dict[str, object]) -> None:
        implementation = ssp["system-implementation"]
        assert isinstance(implementation, dict)
        components = implementation["components"]
        assert isinstance(components, list)
        assert components[0]["type"] == "this-system"
        assert {c["title"] for c in components[1:]} == {
            "Ubuntu 22.04 web server",
            "PostgreSQL 15",
        }

    def test_one_implemented_requirement_per_control(
        self, ssp: dict[str, object], controls: list[Control]
    ) -> None:
        implementation = ssp["control-implementation"]
        assert isinstance(implementation, dict)
        requirements = implementation["implemented-requirements"]
        assert isinstance(requirements, list)
        assert [r["control-id"] for r in requirements] == [c.id for c in controls]
        for requirement in requirements:
            assert requirement["props"] == [
                {"name": "implementation-status", "value": "not-assessed"}
            ]

    def test_statuses_appear_hyphenated(
        self,
        system: SystemDescription,
        categorization: Categorization,
        controls: list[Control],
    ) -> None:
        document = build_oscal_ssp(system, categorization, controls, {"ac-2": "not_implemented"})
        requirements = document["system-security-plan"]["control-implementation"][
            "implemented-requirements"
        ]
        by_id = {r["control-id"]: r for r in requirements}
        assert by_id["ac-2"]["props"][0]["value"] == "not-implemented"

    def test_uuids_are_deterministic_and_unique(
        self,
        system: SystemDescription,
        categorization: Categorization,
        controls: list[Control],
        ssp: dict[str, object],
    ) -> None:
        again = build_oscal_ssp(system, categorization, controls)["system-security-plan"]
        assert isinstance(again, dict)
        assert again["uuid"] == ssp["uuid"]
        requirements = again["control-implementation"]["implemented-requirements"]
        uuids = [r["uuid"] for r in requirements]
        assert len(set(uuids)) == len(uuids)


class TestWriteSsp:
    def test_writes_both_files(
        self,
        tmp_path: Path,
        system: SystemDescription,
        categorization: Categorization,
        controls: list[Control],
    ) -> None:
        md_path, json_path = write_ssp(system, categorization, controls, tmp_path / "out")
        assert md_path.name == "ssp.md"
        assert json_path.name == "ssp.json"
        assert "# System Security Plan: Fixture System" in md_path.read_text(encoding="utf-8")
        document = json.loads(json_path.read_text(encoding="utf-8"))
        assert "system-security-plan" in document
