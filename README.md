# Castellan

A command-line NIST 800-53 / RMF compliance toolkit. Castellan takes a
plain-language description of an information system, derives its FIPS-199
categorization and SP 800-53B control baseline, generates a System Security
Plan skeleton, scans a Linux host with read-only CIS/STIG-style hardening
checks, and produces a control-by-control compliance report (Markdown + OSCAL).

> **Status:** under construction — built in phases per [SPEC.md](SPEC.md).
> Currently implemented: FIPS-199 categorization and baseline selection.

## Quickstart

```sh
pip install -e .[dev]
castellan categorize examples/sample_system.yaml
```

## Development

```sh
ruff check .
mypy
pytest
```

See [SPEC.md](SPEC.md) for the full design and build plan.
