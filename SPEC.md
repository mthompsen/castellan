# Castellan — NIST 800-53 / RMF Compliance Toolkit

> **Design & build specification.** This document is the source of truth for building the tool. It is written to be handed to an autonomous coding agent (Claude Code). Build in the phase order given. Do not skip the tests or the README — for this project the repository itself is the deliverable, and engineering hygiene is part of the point.

*(Codename "Castellan" — the officer historically responsible for a fortress's defenses. Rename freely; the CLI command below assumes `castellan`.)*

---

## 1. One-line description

A command-line toolkit that takes a plain-language description of an information system, derives its NIST 800-53 control baseline, generates a System Security Plan (SSP) skeleton, scans a Linux host for a set of CIS/STIG-style hardening checks, and produces a control-by-control compliance report that maps every technical finding back to the 800-53 control it satisfies or fails — emitting both human-readable reports and machine-readable OSCAL.

## 2. Goals

- Demonstrate end-to-end understanding of the RMF lifecycle: **Categorize → Select → Implement → Assess**.
- Produce artifacts a real assessor would recognize: a FIPS-199 categorization, a selected 800-53B baseline, an SSP, assessment results, and a POA&M.
- Bridge governance (controls/documentation) and engineering (live host state) via an explicit, auditable mapping.
- Be self-contained, fully **defensive** (it audits a host you own for compliance — it never exploits anything), and run on a stock Linux box with no external services required for the core flow.

## 3. Non-goals

- Not a vulnerability scanner, exploit tool, or network scanner. It inspects the local host's configuration only.
- Not a full GRC platform. No multi-tenant DB, no auth, no cloud. Local files only.
- Not a complete implementation of all ~1000 controls or all CIS checks. A curated, correct subset is the point. Breadth is a stretch goal; correctness and the mapping are the core.

## 4. Domain background (so the implementation is accurate)

The agent must encode this domain logic correctly. Key references:

- **FIPS-199** — security categorization. The system is rated Low/Moderate/High independently for **Confidentiality, Integrity, Availability**. The overall categorization is the **high-water mark** (the highest of the three).
- **FIPS-200 / SP 800-53B** — the overall categorization selects a control **baseline**: Low, Moderate, or High. A baseline is a named subset of the full 800-53 catalog.
- **SP 800-53 Rev 5** — the control catalog. Controls are grouped into **20 families** identified by two-letter prefixes: AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR. Each control has an ID (e.g. `ac-2`), a title, and a statement (often with parts/items).
- **SSP (System Security Plan, per SP 800-18)** — documents the system and, for each in-scope control, how it is implemented and by whom.
- **POA&M (Plan of Action & Milestones)** — the running list of deficiencies (failed/partial controls) with remediation plans.
- **CCI (Control Correlation Identifier)** — DISA's mechanism that maps individual STIG check items to specific 800-53 control statements. This is the real-world basis for "this technical check proves this control." Our mapping table is a hand-curated analog of CCI for the checks we implement.
- **OSCAL (Open Security Controls Assessment Language)** — NIST's machine-readable JSON/XML format. Relevant models: `catalog`, `profile` (a baseline), `system-security-plan`, `assessment-results`, `plan-of-action-and-milestones`.

## 5. Data sources

- NIST publishes the 800-53 Rev 5 catalog and the 800-53B Low/Moderate/High baselines as OSCAL JSON in the GitHub repo **`usnistgov/oscal-content`** (under the `nist.gov/SP800-53/rev5/json/` path).
- **Build step:** write a small `scripts/fetch_oscal.py` that downloads the catalog and the three baseline profile JSON files into `data/oscal/`, then caches them. **Verify the exact filenames against the live repo at build time** rather than trusting a hardcoded URL — confirm the catalog and baseline filenames in the repo before wiring them in. Cache locally so the core flow runs offline after first fetch.

## 6. Users & primary use cases

1. *"I have a system. What controls apply and what does my SSP look like?"* → `castellan ssp generate`.
2. *"Is this Linux host actually configured the way the controls require?"* → `castellan scan`.
3. *"Give me one report that says, control by control, where I stand and what's left."* → `castellan report`.

## 7. Tech stack

- **Python 3.11+**
- **Typer** — CLI (type-hint driven, subcommands)
- **Pydantic v2** — all data models and input validation
- **Jinja2** — SSP and report templating
- **PyYAML** — system-description input parsing
- **httpx** — fetching OSCAL content
- **rich** — formatted terminal output (tables, status colors)
- **pytest** + **pytest-cov** — testing
- **ruff** + **mypy** — lint and type-check (must pass clean)
- Packaging via **pyproject.toml** (hatchling or setuptools); installable with `pip install -e .` exposing the `castellan` entry point.
- *(Stretch only)* **FastAPI** + a single static HTML/JS page for the dashboard.

Keep dependencies minimal. No database. No network calls in the core flow after the one-time OSCAL fetch.

## 8. Repository layout

```
castellan/
├── README.md                  # quickstart, screenshots, sample run, architecture diagram
├── SPEC.md                    # this file
├── pyproject.toml
├── LICENSE                    # MIT
├── .github/workflows/ci.yml   # run ruff, mypy, pytest on push
├── data/
│   ├── oscal/                 # cached NIST OSCAL catalog + baselines (gitignored or LFS)
│   └── mappings/
│       └── check_control_map.yaml   # check_id -> [800-53 control ids]  (curated)
├── examples/
│   └── sample_system.yaml     # a worked example system description
├── scripts/
│   └── fetch_oscal.py
├── src/castellan/
│   ├── __init__.py
│   ├── cli.py                 # Typer app, wires subcommands
│   ├── models.py              # Pydantic models (section 9)
│   ├── catalog.py             # load/parse OSCAL catalog + resolve a baseline -> controls
│   ├── categorize.py          # FIPS-199 high-water-mark -> baseline selection
│   ├── ssp.py                 # build SSP model, render markdown + OSCAL SSP json
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── base.py            # Check abstract base class + CheckResult
│   │   ├── runner.py          # discover + run checks, collect results
│   │   └── checks/            # one module per check group (ssh, accounts, files, services...)
│   ├── mapping.py             # load check->control map; join findings to controls
│   ├── report.py              # combined compliance report + POA&M (markdown + json + OSCAL)
│   └── templates/             # jinja2: ssp.md.j2, report.md.j2, poam.md.j2
└── tests/
    ├── test_categorize.py
    ├── test_catalog.py
    ├── test_scanner.py        # uses fixture files, not the real host
    ├── test_mapping.py
    └── test_report.py
```

## 9. Data models (Pydantic v2)

Implement these as the contract between modules.

**Enums**
- `Impact = Literal["low", "moderate", "high"]`
- `ControlStatus = Literal["implemented", "partial", "not_implemented", "not_assessed", "not_applicable"]`
- `CheckOutcome = Literal["pass", "fail", "error", "not_applicable"]`

**`SystemDescription`** (parsed from `sample_system.yaml`)
- `name: str`
- `system_id: str`
- `description: str`
- `owner: str`
- `information_types: list[InformationType]`
- `components: list[str]` (free text, e.g. "Ubuntu 22.04 web server", "PostgreSQL 15")
- `confidentiality: Impact`, `integrity: Impact`, `availability: Impact` *(can be stated directly, or derived from information_types — support both)*

**`InformationType`**
- `name: str`, `confidentiality: Impact`, `integrity: Impact`, `availability: Impact`

**`Categorization`** (output of `categorize.py`)
- `confidentiality: Impact`, `integrity: Impact`, `availability: Impact`
- `overall: Impact` (high-water mark across the three)
- `selected_baseline: Impact`

**`Control`** (parsed from OSCAL catalog)
- `id: str` (e.g. `ac-2`), `family: str` (e.g. `AC`), `title: str`, `statement: str`, `in_baseline: bool`

**`CheckResult`** (output of one scanner check)
- `check_id: str`, `title: str`, `outcome: CheckOutcome`, `detail: str`, `evidence: str | None`, `remediation: str`

**`ControlAssessment`** (output of `mapping.py` — the heart of the tool)
- `control: Control`
- `mapped_checks: list[CheckResult]`
- `status: ControlStatus` *(rules: all mapped checks pass → implemented; some pass → partial; all fail → not_implemented; no mapped checks → not_assessed)*

**`POAMItem`**
- `control_id: str`, `weakness: str`, `source_check: str`, `remediation: str`, `status: Literal["open"]`

## 10. Component specifications

### 10.1 `categorize.py`
- Input: `SystemDescription`. Output: `Categorization`.
- If information types are provided, take the high-water mark across all types per CIA pillar; otherwise use the directly stated CIA values.
- `overall` = max(confidentiality, integrity, availability) on the ordering low < moderate < high.
- `selected_baseline` = `overall`.
- Pure function, fully unit-tested with edge cases (mixed types, single type, direct values).

### 10.2 `catalog.py`
- Load the cached OSCAL catalog JSON and the baseline profile JSON for the selected impact level.
- Parse controls into `Control` objects. Derive `family` from the control id prefix.
- Resolve the baseline: a control's `in_baseline` is true if it appears in the selected baseline profile's import/include set. (OSCAL profiles reference controls by id; resolve those references against the catalog.)
- Expose `load_controls(baseline: Impact) -> list[Control]` returning only in-baseline controls, sorted by family then id.

### 10.3 `scanner/`
- `base.Check`: abstract class with `check_id`, `title`, `remediation`, and a `run() -> CheckResult` method. Each check reads host state read-only (parse a config file, stat a path, inspect a service) and never modifies anything.
- `runner.run_all() -> list[CheckResult]`: discovers all registered checks, runs them, catches exceptions per-check and records them as `outcome="error"` (one bad check must never crash the run).
- Implement **at least 18 checks** across these groups (each must cite what it inspects and a real remediation). Suggested set:
  - **SSH** (`sshd_config`): PermitRootLogin no; PasswordAuthentication considerations; Protocol/ciphers; idle timeout (`ClientAliveInterval`).
  - **Accounts** (`/etc/login.defs`, `/etc/passwd`, `/etc/shadow`): password max age; min length policy; no UID-0 accounts other than root; no empty passwords.
  - **Filesystem perms**: `/etc/shadow` is `0640`/`0600` and owned root; `/etc/passwd` perms; world-writable files in system dirs (bounded search).
  - **Services**: `auditd` installed/running; firewall (`ufw`/`firewalld`/nftables) active; `cron` perms.
  - **Logging**: rsyslog/journald present; log file perms.
  - **Updates**: unattended-upgrades / automatic security updates configured (best-effort detection).
- Each check must run gracefully on a host where the relevant file/service is absent (return `not_applicable`, not `error`, when truly N/A).
- **Tests use fixture config files in `tests/fixtures/`, never the real host**, so the suite is deterministic in CI.

### 10.4 `mapping.py`
- Load `data/mappings/check_control_map.yaml`: a hand-curated dict of `check_id -> [control_id, ...]`. Every implemented check must map to at least one real 800-53 control (e.g. SSH root-login → `ac-6`, `ia-2`; password age → `ia-5`; auditd → `au-2`, `au-12`; firewall → `sc-7`; shadow perms → `ac-3`, `sc-28`). Get these mappings right — accuracy here is what an assessor will scrutinize.
- `assess(controls, results) -> list[ControlAssessment]`: for each in-baseline control, attach the `CheckResult`s whose mapping includes that control, then compute `status` per the rules in §9.
- Controls with no mapped check are `not_assessed` (this is honest and correct — most controls are organizational, not technically testable; do **not** fake a pass).

### 10.5 `ssp.py`
- Build an SSP from `SystemDescription` + `Categorization` + in-baseline controls.
- Render two outputs:
  - **`ssp.md`** via Jinja2: cover section (system identity, owner, categorization rationale), then a section per control family, then per control: id, title, statement, and an **implementation status block** to be filled in (defaulting to `not_assessed`, or populated from assessment results if available).
  - **`ssp.json`**: a valid-shaped OSCAL `system-security-plan` document (system-characteristics with the FIPS-199 categorization, and an implemented-requirements entry per control). Aim for structural fidelity to the OSCAL SSP model; it does not need to pass the full NIST validator in the MVP but the shape must be correct and documented.

### 10.6 `report.py`
- Combine controls + assessments into:
  - **`compliance_report.md`**: executive summary (counts by status, % of assessable controls passing), a per-family table, and a detailed per-control section showing mapped checks and their evidence. Use color/emoji status in the terminal view via `rich`, plain text in the file.
  - **`poam.md`** and **`poam.json`** (OSCAL `plan-of-action-and-milestones` shape): one item per failed/partial control, with the failing check as the source and its remediation text.
  - **`assessment_results.json`**: OSCAL `assessment-results` shape capturing each check as an observation/finding.

## 11. CLI specification (Typer)

```
castellan fetch                          # run scripts/fetch_oscal.py (one-time setup)
castellan categorize SYSTEM.yaml         # print FIPS-199 categorization + selected baseline
castellan ssp generate SYSTEM.yaml [-o OUTDIR]
                                         # writes ssp.md + ssp.json
castellan scan [--out OUTDIR] [--json]   # runs host checks, prints rich table of results
castellan report SYSTEM.yaml [-o OUTDIR] # full flow: categorize -> select -> scan ->
                                         #   map -> compliance_report.md + poam + oscal
castellan checks list                    # list all implemented checks and their mapped controls
```

- Every command exits non-zero on error with a clear message. `--help` works at every level.
- `report` is the headline command: one invocation produces the whole evidence package.

## 12. Output artifacts (the portfolio payoff)

After `castellan report examples/sample_system.yaml -o out/`, the `out/` directory contains: `ssp.md`, `ssp.json`, `compliance_report.md`, `poam.md`, `poam.json`, `assessment_results.json`. The README should show a real sample run against an example host with these files committed under `examples/output/` so a reviewer sees the result without running anything.

## 13. Build phases (do in order)

1. **Scaffold + categorize.** Repo layout, packaging, `categorize.py` + tests, CLI skeleton with `categorize`. Green CI.
2. **Catalog.** `fetch_oscal.py`, `catalog.py` baseline resolution + tests. `categorize` and a stub `ssp generate` produce a control list.
3. **SSP.** `ssp.py` + templates → `ssp.md` and OSCAL `ssp.json`. Worked example.
4. **Scanner.** `scanner/` with ≥18 checks, fixture-based tests, `scan` command with rich output.
5. **Mapping + report.** `mapping.yaml`, `mapping.py`, `report.py`, POA&M + OSCAL assessment results. `report` end-to-end.
6. **Polish.** README with architecture diagram + sample output, screenshots/asciinema, docstrings, `--help` text, coverage ≥80%.
7. *(Stretch)* FastAPI dashboard; OpenSCAP integration as an alternate scan backend; multiple OS profiles; OSCAL validation against NIST's validator.

## 14. Testing & quality requirements

- `pytest` suite covers categorize logic, baseline resolution, every check (via fixtures), mapping/status computation, and report counts. Target ≥80% coverage.
- `ruff` and `mypy --strict` pass clean.
- CI workflow runs lint, type-check, and tests on every push.
- No secrets, no network in tests, no host mutation anywhere in the codebase.

## 15. Acceptance criteria

- [ ] `pip install -e .` then `castellan --help` works; all subcommands documented.
- [ ] `castellan categorize examples/sample_system.yaml` prints correct CIA values, high-water-mark overall, and selected baseline.
- [ ] `castellan ssp generate` emits an `ssp.md` whose control set exactly matches the selected 800-53B baseline, plus a structurally correct OSCAL `ssp.json`.
- [ ] `castellan scan` runs ≥18 read-only checks on a Linux host and prints a status table; one failing/erroring check never aborts the run.
- [ ] Every check maps to at least one correct 800-53 control; `castellan checks list` shows the mapping.
- [ ] `castellan report` produces the full artifact set in §12, with control statuses computed honestly (unmapped controls = `not_assessed`, never auto-passed).
- [ ] CI is green; coverage ≥80%; README shows a real sample run with committed example output.

## 16. Notes to the implementer

- When in doubt about OSCAL structure, fetch and inspect a real NIST OSCAL SSP example from `usnistgov/oscal-content` and mirror its shape rather than guessing.
- Prefer correctness and honesty in the compliance logic over impressive-looking pass rates. A report that truthfully says "62% of assessable controls pass, 14 POA&M items open" is far more credible than one that claims full compliance — and credibility is the entire point of this project.
- Write the README for a human reviewer (a scholarship committee or interviewer): lead with what RMF is, what the tool does in one sentence, an architecture diagram, and a sample run. Make the engineering legible.
