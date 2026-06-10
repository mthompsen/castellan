# Castellan

A command-line NIST 800-53 / RMF compliance toolkit. Castellan takes a
plain-language description of an information system, derives its FIPS-199
categorization and SP 800-53B control baseline, generates a System Security
Plan skeleton, scans a Linux host with read-only CIS/STIG-style hardening
checks, and produces a control-by-control compliance report (Markdown + OSCAL).

> **Status:** under construction — built in phases per [SPEC.md](SPEC.md).
> The full pipeline is implemented: FIPS-199 categorization, 800-53B baseline
> selection, SSP generation (markdown + OSCAL), a 20-check read-only host
> scanner, and the check→control mapping that powers the compliance report
> and POA&M. See [examples/output/](examples/output/) for a generated sample.

## Quickstart

```sh
pip install -e .[dev]
castellan fetch                                  # one-time OSCAL download
castellan categorize examples/sample_system.yaml
castellan checks list                            # checks + mapped controls
castellan report examples/sample_system.yaml -o out/   # the whole package
```

## Development

```sh
ruff check .
mypy
pytest
```

See [SPEC.md](SPEC.md) for the full design and build plan.
