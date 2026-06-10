"""Tests for FIPS-199 categorization and baseline selection."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from castellan.categorize import categorize, high_water
from castellan.models import (
    InformationType,
    SystemDescription,
    load_system_description,
)

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def make_system(**overrides: object) -> SystemDescription:
    base: dict[str, object] = {
        "name": "Test System",
        "system_id": "TS-1",
        "description": "A system under test.",
        "owner": "Test Owner",
        "confidentiality": "low",
        "integrity": "low",
        "availability": "low",
    }
    base.update(overrides)
    return SystemDescription.model_validate(base)


class TestHighWater:
    def test_single_value(self) -> None:
        assert high_water("moderate") == "moderate"

    @pytest.mark.parametrize(
        ("levels", "expected"),
        [
            (("low", "low", "low"), "low"),
            (("low", "moderate"), "moderate"),
            (("moderate", "high", "low"), "high"),
            (("high", "high"), "high"),
            (("low", "moderate", "high"), "high"),
        ],
    )
    def test_returns_highest(self, levels: tuple[str, ...], expected: str) -> None:
        assert high_water(*levels) == expected  # type: ignore[arg-type]

    def test_not_alphabetical_ordering(self) -> None:
        # Alphabetically "moderate" > "low" happens to hold, but "high" < "low"
        # does not — this guards against accidental string comparison.
        assert high_water("low", "high") == "high"
        assert high_water("moderate", "high") == "high"


class TestCategorizeDirectValues:
    def test_uses_stated_values(self) -> None:
        system = make_system(confidentiality="moderate", integrity="low", availability="low")
        result = categorize(system)
        assert result.confidentiality == "moderate"
        assert result.integrity == "low"
        assert result.availability == "low"

    def test_overall_is_high_water_mark(self) -> None:
        system = make_system(confidentiality="low", integrity="high", availability="moderate")
        result = categorize(system)
        assert result.overall == "high"

    def test_baseline_equals_overall(self) -> None:
        system = make_system(confidentiality="moderate", integrity="low", availability="low")
        result = categorize(system)
        assert result.selected_baseline == result.overall == "moderate"

    def test_all_low_selects_low_baseline(self) -> None:
        result = categorize(make_system())
        assert result.overall == "low"
        assert result.selected_baseline == "low"


class TestCategorizeFromInformationTypes:
    def test_single_type(self) -> None:
        system = make_system(
            confidentiality=None,
            integrity=None,
            availability=None,
            information_types=[
                {
                    "name": "PII",
                    "confidentiality": "moderate",
                    "integrity": "low",
                    "availability": "low",
                }
            ],
        )
        result = categorize(system)
        assert result.confidentiality == "moderate"
        assert result.integrity == "low"
        assert result.availability == "low"
        assert result.overall == "moderate"

    def test_high_water_mark_per_pillar_across_types(self) -> None:
        system = make_system(
            confidentiality=None,
            integrity=None,
            availability=None,
            information_types=[
                InformationType(
                    name="A", confidentiality="high", integrity="low", availability="low"
                ),
                InformationType(
                    name="B", confidentiality="low", integrity="moderate", availability="low"
                ),
                InformationType(
                    name="C", confidentiality="low", integrity="low", availability="moderate"
                ),
            ],
        )
        result = categorize(system)
        assert result.confidentiality == "high"
        assert result.integrity == "moderate"
        assert result.availability == "moderate"
        assert result.overall == "high"
        assert result.selected_baseline == "high"

    def test_information_types_take_precedence_over_direct_values(self) -> None:
        system = make_system(
            confidentiality="high",
            integrity="high",
            availability="high",
            information_types=[
                InformationType(
                    name="Public data",
                    confidentiality="low",
                    integrity="low",
                    availability="low",
                )
            ],
        )
        result = categorize(system)
        assert result.overall == "low"


class TestSystemDescriptionValidation:
    def test_rejects_missing_impact_source(self) -> None:
        with pytest.raises(ValidationError, match="information_types"):
            make_system(confidentiality=None, integrity=None, availability=None)

    def test_rejects_partial_direct_values(self) -> None:
        with pytest.raises(ValidationError):
            make_system(availability=None)

    def test_rejects_invalid_impact_level(self) -> None:
        with pytest.raises(ValidationError):
            make_system(confidentiality="critical")


class TestSampleSystemFile:
    def test_loads_and_categorizes(self) -> None:
        system = load_system_description(EXAMPLES_DIR / "sample_system.yaml")
        assert system.system_id == "EBP-001"
        assert len(system.information_types) == 3
        result = categorize(system)
        assert result.confidentiality == "moderate"
        assert result.integrity == "moderate"
        assert result.availability == "low"
        assert result.overall == "moderate"
        assert result.selected_baseline == "moderate"
