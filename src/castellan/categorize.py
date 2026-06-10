"""FIPS-199 security categorization and SP 800-53B baseline selection.

Pure functions: a system's CIA impact levels are taken from its information
types (high-water mark per pillar) or, absent those, its directly stated
values. The overall categorization is the high-water mark across the three
pillars and selects the control baseline of the same level (FIPS-200).
"""

from __future__ import annotations

from castellan.models import Categorization, Impact, SystemDescription

_IMPACT_ORDER: dict[Impact, int] = {"low": 0, "moderate": 1, "high": 2}


def high_water(first: Impact, *rest: Impact) -> Impact:
    """Return the highest impact level on the ordering low < moderate < high."""
    return max(first, *rest, key=lambda level: _IMPACT_ORDER[level]) if rest else first


def categorize(system: SystemDescription) -> Categorization:
    """Derive the FIPS-199 categorization and selected baseline for a system."""
    if system.information_types:
        confidentiality = high_water(*(t.confidentiality for t in system.information_types))
        integrity = high_water(*(t.integrity for t in system.information_types))
        availability = high_water(*(t.availability for t in system.information_types))
    else:
        # The SystemDescription validator guarantees these are set when no
        # information types are given.
        assert system.confidentiality is not None
        assert system.integrity is not None
        assert system.availability is not None
        confidentiality = system.confidentiality
        integrity = system.integrity
        availability = system.availability

    overall = high_water(confidentiality, integrity, availability)
    return Categorization(
        confidentiality=confidentiality,
        integrity=integrity,
        availability=availability,
        overall=overall,
        selected_baseline=overall,
    )
