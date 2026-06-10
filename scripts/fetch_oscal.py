"""One-time setup: download NIST OSCAL content into data/oscal/.

Thin wrapper around :mod:`castellan.fetch` so the same logic backs both this
script and the ``castellan fetch`` command. Run with ``--force`` to re-download
cached files.
"""

from __future__ import annotations

import sys

from castellan.fetch import DEFAULT_DATA_DIR, fetch_oscal_content


def main(argv: list[str]) -> int:
    force = "--force" in argv
    try:
        downloaded = fetch_oscal_content(force=force)
    except Exception as exc:  # report any failure clearly, exit non-zero
        print(f"error: failed to fetch OSCAL content: {exc}", file=sys.stderr)
        return 1
    if downloaded:
        for path in downloaded:
            print(f"downloaded {path.name}")
    else:
        print(f"all OSCAL files already cached in {DEFAULT_DATA_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
