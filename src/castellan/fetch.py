"""Download and cache NIST OSCAL content (800-53 rev5 catalog + baselines).

Filenames were verified against the live ``usnistgov/oscal-content`` repo
(``nist.gov/SP800-53/rev5/json/`` on the ``main`` branch). Files are cached in
``data/oscal/``; after the first fetch the core flow runs fully offline.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from castellan.models import Impact

_BASE_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json"
)

CATALOG_FILENAME = "NIST_SP-800-53_rev5_catalog.json"
PROFILE_FILENAMES: dict[Impact, str] = {
    "low": "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
    "moderate": "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
    "high": "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
}

# Repo root when running from a source checkout (src/castellan/fetch.py -> repo).
DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "oscal"


def fetch_oscal_content(data_dir: Path = DEFAULT_DATA_DIR, *, force: bool = False) -> list[Path]:
    """Download the 800-53 catalog and the three baseline profiles into *data_dir*.

    Files already present are kept unless *force* is true. Returns the paths
    of the files that were actually downloaded.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    downloaded: list[Path] = []
    filenames = [CATALOG_FILENAME, *PROFILE_FILENAMES.values()]
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        for filename in filenames:
            target = data_dir / filename
            if target.exists() and not force:
                continue
            response = client.get(f"{_BASE_URL}/{filename}")
            response.raise_for_status()
            target.write_bytes(response.content)
            downloaded.append(target)
    return downloaded
