"""Tests for OSCAL catalog parsing, baseline resolution, and fetch caching.

Unit tests run against miniature OSCAL fixtures in ``tests/fixtures/oscal/``;
no network and no dependence on the real downloaded content. A final
integration test exercises the real cached NIST files when present (it is
skipped in CI, where ``data/oscal/`` does not exist).
"""

import shutil
from pathlib import Path
from typing import Any, ClassVar

import pytest

from castellan.catalog import (
    load_baseline_ids,
    load_catalog_controls,
    load_controls,
)
from castellan.fetch import (
    CATALOG_FILENAME,
    DEFAULT_DATA_DIR,
    PROFILE_FILENAMES,
    fetch_oscal_content,
)
from castellan.models import Control

FIXTURES = Path(__file__).parent / "fixtures" / "oscal"
MINI_CATALOG = FIXTURES / "mini_catalog.json"
MINI_PROFILE = FIXTURES / "mini_profile_moderate.json"


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """A data directory holding the mini fixtures under the real NIST filenames."""
    shutil.copy(MINI_CATALOG, tmp_path / CATALOG_FILENAME)
    shutil.copy(MINI_PROFILE, tmp_path / PROFILE_FILENAMES["moderate"])
    return tmp_path


class TestCatalogParsing:
    @pytest.fixture(scope="class")
    def controls(self) -> dict[str, Control]:
        return {c.id: c for c in load_catalog_controls(MINI_CATALOG)}

    def test_parses_all_controls_and_enhancements(self, controls: dict[str, Control]) -> None:
        assert set(controls) == {"ac-1", "ac-2", "ac-2.1", "ac-2.13", "ac-10", "sc-7", "sc-9"}

    def test_family_derived_from_id_prefix(self, controls: dict[str, Control]) -> None:
        assert controls["ac-2"].family == "AC"
        assert controls["sc-7"].family == "SC"
        assert controls["ac-2.1"].family == "AC"

    def test_statement_flattens_labeled_items(self, controls: dict[str, Control]) -> None:
        statement = controls["ac-2"].statement
        assert "a. Define and document the types of accounts allowed;" in statement
        assert statement.index("a. Define") < statement.index("b. Require")

    def test_statement_excludes_guidance(self, controls: dict[str, Control]) -> None:
        assert "Guidance text" not in controls["ac-2"].statement

    def test_assignment_param_substitution(self, controls: dict[str, Control]) -> None:
        assert (
            "[Assignment: organization-defined prerequisites and criteria]"
            in controls["ac-2"].statement
        )
        assert "{{" not in controls["ac-2"].statement

    def test_selection_param_substitution(self, controls: dict[str, Control]) -> None:
        assert "[Selection (one-or-more): account; account type]" in controls["ac-10"].statement

    def test_enhancement_inherits_parent_params(self, controls: dict[str, Control]) -> None:
        assert (
            "[Assignment: organization-defined prerequisites and criteria]"
            in controls["ac-2.1"].statement
        )

    def test_withdrawn_control_has_empty_statement(self, controls: dict[str, Control]) -> None:
        assert controls["sc-9"].statement == ""

    def test_in_baseline_defaults_false(self, controls: dict[str, Control]) -> None:
        assert all(not c.in_baseline for c in controls.values())


class TestBaselineResolution:
    def test_load_baseline_ids(self) -> None:
        assert load_baseline_ids(MINI_PROFILE) == {"ac-1", "ac-2", "ac-2.13", "ac-10", "sc-7"}

    def test_load_controls_filters_to_baseline(self, data_dir: Path) -> None:
        controls = load_controls("moderate", data_dir)
        assert [c.id for c in controls] == ["ac-1", "ac-2", "ac-2.13", "ac-10", "sc-7"]
        assert all(c.in_baseline for c in controls)

    def test_sorting_is_numeric_not_lexicographic(self, data_dir: Path) -> None:
        ids = [c.id for c in load_controls("moderate", data_dir)]
        # Lexicographic sorting would put "ac-10" before "ac-2".
        assert ids.index("ac-2") < ids.index("ac-10")
        # Enhancements sort with their parent control, before later controls.
        assert ids.index("ac-2") < ids.index("ac-2.13") < ids.index("ac-10")

    def test_missing_catalog_raises_with_fetch_hint(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="castellan fetch"):
            load_controls("moderate", tmp_path)


class _StubResponse:
    content = b'{"stub": true}'

    def raise_for_status(self) -> None:
        pass


class _StubClient:
    """Stands in for httpx.Client; records requested URLs, never touches the network."""

    requested: ClassVar[list[str]] = []

    def __init__(self, **_: Any) -> None:
        pass

    def __enter__(self) -> "_StubClient":
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def get(self, url: str) -> _StubResponse:
        _StubClient.requested.append(url)
        return _StubResponse()


class TestFetchCaching:
    @pytest.fixture(autouse=True)
    def stub_httpx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _StubClient.requested = []
        monkeypatch.setattr("castellan.fetch.httpx.Client", _StubClient)

    def test_downloads_all_files_when_cache_empty(self, tmp_path: Path) -> None:
        downloaded = fetch_oscal_content(tmp_path)
        assert len(downloaded) == 4
        assert len(_StubClient.requested) == 4
        assert (tmp_path / CATALOG_FILENAME).read_bytes() == b'{"stub": true}'

    def test_skips_cached_files(self, tmp_path: Path) -> None:
        for name in (CATALOG_FILENAME, *PROFILE_FILENAMES.values()):
            (tmp_path / name).write_text("cached")
        downloaded = fetch_oscal_content(tmp_path)
        assert downloaded == []
        assert _StubClient.requested == []
        assert (tmp_path / CATALOG_FILENAME).read_text() == "cached"

    def test_force_redownloads(self, tmp_path: Path) -> None:
        for name in (CATALOG_FILENAME, *PROFILE_FILENAMES.values()):
            (tmp_path / name).write_text("cached")
        downloaded = fetch_oscal_content(tmp_path, force=True)
        assert len(downloaded) == 4


@pytest.mark.skipif(
    not (DEFAULT_DATA_DIR / CATALOG_FILENAME).exists(),
    reason="real OSCAL content not fetched (run 'castellan fetch')",
)
class TestRealNistContent:
    """Sanity checks against the real cached NIST files (skipped in CI)."""

    def test_moderate_baseline_resolves(self) -> None:
        controls = load_controls("moderate")
        ids = {c.id for c in controls}
        profile_path = DEFAULT_DATA_DIR / PROFILE_FILENAMES["moderate"]
        assert len(controls) == len(load_baseline_ids(profile_path))
        assert {"ac-2", "au-2", "ia-5", "sc-7", "si-2"} <= ids
        assert all(c.in_baseline for c in controls)

    def test_baseline_sizes_are_ordered(self) -> None:
        low = load_controls("low")
        moderate = load_controls("moderate")
        high = load_controls("high")
        assert len(low) < len(moderate) < len(high)
        assert {c.id for c in low} <= {c.id for c in moderate} <= {c.id for c in high}

    def test_ac2_parses_cleanly(self) -> None:
        ac2 = next(c for c in load_controls("moderate") if c.id == "ac-2")
        assert ac2.title == "Account Management"
        assert ac2.family == "AC"
        assert "{{" not in ac2.statement
        assert ac2.statement.startswith("a. Define and document the types of accounts")
