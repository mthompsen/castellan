# Castellan — NIST 800-53 / RMF Compliance Toolkit

> **Design document.** This describes Castellan's architecture, domain logic,
> and design rationale. For a quick tour and sample output, start with the
> [README](README.md).

*(Codename "Castellan" — the officer historically responsible for a fortress's
defenses.)*

---

## 1. One-line description

A command-line toolkit that takes a plain-language description of an
information system, derives its NIST 800-53 control baseline, generates a
System Security Plan (SSP) skeleton, scans a Linux host for a set of
CIS/STIG-style hardening checks, and produces a control-by-control compliance
report that maps every technical finding back to the 800-53 control it
satisfies or fails — emitting both human-readable reports and machine-readable
OSCAL.

## 2. Goals

- Cover the RMF lifecycle end to end:
  **Categorize → Select → Implement → Assess**.
- Produce artifacts a real assessor would recognize: a FIPS-199
  categorization, a selected 800-53B baseline, an SSP, assessment results,
  and a POA&M.
- Bridge governance (controls/documentation) and engineering (live host
  state) via an explicit, auditable mapping.
- Be self-contained, fully **defensive** (it audits a host you own for
  compliance — it never exploits anything), and run on a stock Linux box with
  no external services required for the core flow.

## 3. Non-goals

- Not a vulnerability scanner, exploit tool, or network scanner. It inspects
  the local host's configuration only.
- Not a full GRC platform. No multi-tenant DB, no auth, no cloud. Local files
  only.
- Not a complete implementation of all ~1000 controls or all CIS checks. A
  curated, correct subset is the point. Breadth is a stretch goal;
  correctness and the mapping are the core.

## 4. Domain background

Castellan encodes this domain logic. Key references:

- **FIPS-199** — security categorization. The system is rated Low/Moderate/High
  independently for **Confidentiality, Integrity, Availability**. The overall
  categorization is the **high-water mark** (the highest of the three).
- **FIPS-200 / SP 800-53B** — the overall categorization selects a control
  **baseline**: Low, Moderate, or High. A baseline is a named subset of the
  full 800-53 catalog (149, 287, and 370 controls respectively in rev 5).
- **SP 800-53 Rev 5** — the control catalog. Controls are grouped into **20
  families** identified by two-letter prefixes: AC, AT, AU, CA, CM, CP, IA,
  IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR. Each control has an ID
  (e.g. `ac-2`), a title, and a statement (often with parts/items).
- **SSP (System Security Plan, per SP 800-18)** — documents the system and,
  for each in-scope control, how it is implemented and by whom.
- **POA&M (Plan of Action & Milestones)** — the running list of deficiencies
  (failed/partial controls) with remediation plans.
- **CCI (Control Correlation Identifier)** — DISA's mechanism that maps
  individual STIG check items to specific 800-53 control statements. This is
  the real-world basis for "this technical check proves this control."
  Castellan's mapping table is a hand-curated analog of CCI for the checks it
  implements.
- **OSCAL (Open Security Controls Assessment Language)** — NIST's
  machine-readable JSON/XML format. Relevant models: `catalog`, `profile` (a
  baseline), `system-security-plan`, `assessment-results`,
  `plan-of-action-and-milestones`.

## 5. Data sources

- NIST publishes the 800-53 Rev 5 catalog and the 800-53B Low/Moderate/High
  baselines as OSCAL JSON in the GitHub repo **`usnistgov/oscal-content`**
  (under the `nist.gov/SP800-53/rev5/json/` path).
- `castellan fetch` (backed by `castellan/fetch.py`, with
  `scripts/fetch_oscal.py` as a standalone wrapper) downloads the catalog and
  the three baseline profile JSON files into `data/oscal/` and caches them.
  The exact filenames were verified against the live repository rather than
  assumed. After the one-time fetch, the entire core flow runs offline.

## 6. Users & primary use cases

1. *"I have a system. What controls apply and what does my SSP look like?"*
   → `castellan ssp generate`.
2. *"Is this Linux host actually configured the way the controls require?"*
   → `castellan scan`.
3. *"Give me one report that says, control by control, where I stand and
   what's left."* → `castellan report`.

## 7. Tech stack

- **Python 3.11+**
- **Typer** — CLI (type-hint driven, subcommands)
- **Pydantic v2** — all data models and input validation
- **Jinja2** — SSP and report templating
- **PyYAML** — system-description input parsing
- **httpx** — fetching OSCAL content
- **rich** — formatted terminal output (tables, status colors)
- **pytest** + **pytest-cov** — testing
- **ruff** + **mypy --strict** — lint and type-check (pass clean)
- Packaging via **pyproject.toml** (hatchling); installable with
  `pip install -e .` exposing the `castellan` entry point.

Dependencies are minimal. No database. No network calls in the core flow
after the one-time OSCAL fetch.

## 8. Repository layout

```
castellan/
├── README.md                  # quickstart, architecture diagram, sample run
├── SPEC.md                    # this document
├── pyproject.toml
├── LICENSE                    # MIT
├── .github/workflows/ci.yml   # ruff, mypy, pytest + coverage gate on push
├── data/
│   ├── oscal/                 # cached NIST OSCAL catalog + baselines (gitignored)
│   └── mappings/
│       └── check_control_map.yaml   # check_id -> [800-53 control ids]  (curated)
├── examples/
│   ├── sample_system.yaml     # worked example system description
│   └── output/                # real artifact set generated on an Ubuntu host
├── scripts/
│   └── fetch_oscal.py
├── src/castellan/
│   ├── cli.py                 # Typer app, wires subcommands
│   ├── models.py              # Pydantic models (section 9)
│   ├── fetch.py               # OSCAL download + cache
│   ├── catalog.py             # parse OSCAL catalog + resolve a baseline -> controls
│   ├── categorize.py          # FIPS-199 high-water-mark -> baseline selection
│   ├── ssp.py                 # build SSP model, render markdown + OSCAL SSP json
│   ├── scanner/
│   │   ├── host.py            # Host protocol + LinuxHost implementation
│   │   ├── base.py            # Check abstract base class
│   │   ├── runner.py          # run all checks, collect results
│   │   └── checks/            # one module per group: ssh, accounts, files,
│   │                          #   services, logs, updates
│   ├── mapping.py             # load check->control map; join findings to controls
│   ├── report.py              # compliance report + POA&M (markdown + OSCAL)
│   ├── templating.py          # shared Jinja2 environment
│   └── templates/             # ssp.md.j2, report.md.j2, poam.md.j2
└── tests/                     # 208 tests: conftest.py FakeHost, fixtures/,
                               #   one module per component
```

## 9. Data models (Pydantic v2)

These models are the contract between modules.

**Enums**
- `Impact = Literal["low", "moderate", "high"]`
- `ControlStatus = Literal["implemented", "partial", "not_implemented", "not_assessed", "not_applicable"]`
- `CheckOutcome = Literal["pass", "fail", "error", "not_applicable"]`

**`SystemDescription`** (parsed from a system YAML file)
- `name: str`
- `system_id: str`
- `description: str`
- `owner: str`
- `information_types: list[InformationType]`
- `components: list[str]` (free text, e.g. "Ubuntu 22.04 web server", "PostgreSQL 15")
- `confidentiality: Impact`, `integrity: Impact`, `availability: Impact`
  *(stated directly, or derived from information_types — both are supported;
  a model validator requires at least one of the two)*

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
- `status: ControlStatus` *(rules: all mapped checks pass → implemented; some
  pass → partial; all fail → not_implemented; no evidence → not_assessed)*

**`POAMItem`**
- `control_id: str`, `weakness: str`, `source_check: str`, `remediation: str`, `status: Literal["open"]`

## 10. Component specifications

### 10.1 `categorize.py`
- Input: `SystemDescription`. Output: `Categorization`.
- If information types are provided, Castellan takes the high-water mark
  across all types per CIA pillar; otherwise it uses the directly stated CIA
  values.
- `overall` = max(confidentiality, integrity, availability) on the ordering
  low < moderate < high.
- `selected_baseline` = `overall`.
- Pure functions, fully unit-tested with edge cases (mixed types, single
  type, direct values).

### 10.2 `catalog.py`
- Loads the cached OSCAL catalog JSON and the baseline profile JSON for the
  selected impact level.
- Parses controls (including enhancements nested inside controls) into
  `Control` objects. `family` derives from the control id prefix. Statements
  are flattened from OSCAL's part tree with their item labels, and
  `{{ insert: param, ... }}` placeholders render as assessor-style
  `[Assignment: ...]` / `[Selection: ...]` text; enhancements inherit their
  parent control's parameter definitions.
- Resolves the baseline: a control is in the baseline if its id appears in
  the selected profile's `imports[].include-controls[].with-ids` set.
- Exposes `load_controls(baseline: Impact) -> list[Control]` returning only
  in-baseline controls, sorted numerically by family then id (so `ac-2`
  precedes `ac-10`).

### 10.3 `scanner/`
- `host.Host`: a five-method read-only protocol (`read_text`, `exists`,
  `stat`, `iter_files`, `service_active`) through which every check reaches
  the host — there is no write path, making checks read-only by
  construction. `LinuxHost` is the production implementation; tests
  substitute an in-memory `FakeHost`.
- `base.Check`: abstract class with `check_id`, `title`, `remediation`, and a
  `run() -> CheckResult` method. Each check reads host state read-only
  (parses a config file, stats a path, queries a service) and never modifies
  anything.
- `runner.run_all() -> list[CheckResult]`: runs all registered checks,
  catching exceptions per-check and recording them as `outcome="error"` (one
  bad check never crashes the run).
- **20 checks** across six groups, each citing what it inspects and a real
  remediation:
  - **SSH** (`sshd_config`, parsed with sshd semantics — first occurrence
    wins, `Match` blocks ignored): PermitRootLogin; PasswordAuthentication;
    weak protocol/ciphers; idle timeout (`ClientAliveInterval`);
    MaxAuthTries; PermitEmptyPasswords.
  - **Accounts** (`/etc/login.defs`, `pwquality.conf`, `/etc/passwd`,
    `/etc/shadow`): password max age; minimum length policy; expiry warning;
    no UID-0 accounts other than root; no empty passwords.
  - **Filesystem perms**: `/etc/shadow` ≤0640 and root-owned; `/etc/passwd`
    ≤0644; world-writable files in system dirs (bounded search).
  - **Services**: auditd running; firewall (`ufw`/`firewalld`/`nftables`)
    active; `/etc/crontab` perms.
  - **Logging**: rsyslog/journald present; sensitive log file perms.
  - **Updates**: unattended-upgrades / dnf-automatic configured (best-effort
    detection).
- Each check runs gracefully on a host where the relevant file/service is
  absent (returning `not_applicable`, not `error`, when truly N/A).
- **Tests use fixture config files in `tests/fixtures/`, never the real
  host**, so the suite is deterministic in CI and on any OS.

### 10.4 `mapping.py`
- Loads `data/mappings/check_control_map.yaml`: a hand-curated dict of
  `check_id -> [control_id, ...]` with a written rationale per check. Every
  implemented check maps to at least one real 800-53 control (e.g. SSH
  root-login → `ac-6`, `ia-2`; password aging → `ia-5`; auditd → `au-2`,
  `au-12`; firewall → `sc-7`; shadow perms → `ac-3`, `sc-28`). Accuracy here
  is what an assessor scrutinizes; tests verify every check is mapped, no
  stale entries survive, and every mapped control exists in the rev 5
  catalog and the moderate baseline.
- `assess(controls, results) -> list[ControlAssessment]`: for each
  in-baseline control, attaches the `CheckResult`s whose mapping includes
  that control, then computes `status` per the rules in §9. Checks that
  return `not_applicable` or `error` carry no evidence either way and are
  excluded from the pass/fail computation.
- Controls with no mapped check are `not_assessed` (honest and correct —
  most controls are organizational, not technically testable; Castellan
  never fakes a pass).

### 10.5 `ssp.py`
- Builds an SSP from `SystemDescription` + `Categorization` + in-baseline
  controls.
- Renders two outputs:
  - **`ssp.md`** via Jinja2: cover section (system identity, owner,
    categorization rationale), then a section per control family, then per
    control: id, title, statement, and an **implementation status block**
    (defaulting to `not_assessed`, or populated from assessment results when
    generated via `castellan report`).
  - **`ssp.json`**: an OSCAL `system-security-plan` document
    (system-characteristics with the FIPS-199 categorization as
    `fips-199-<level>` values, and an implemented-requirements entry per
    control). The shape mirrors the example SSP published in
    `usnistgov/oscal-content`; it aims for structural fidelity rather than
    full schema validation. Identifiers are deterministic UUIDv5 seeded from
    the system id, so regeneration yields stable ids.

### 10.6 `report.py`
- Combines controls + assessments into:
  - **`compliance_report.md`**: executive summary (counts by status, % of
    assessable controls passing), a per-family table, and a detailed
    per-control section showing mapped checks and their evidence. The
    terminal view uses `rich` color; the file is plain markdown.
  - **`poam.md`** and **`poam.json`** (OSCAL `plan-of-action-and-milestones`
    shape): one item per failed/partial control, with the failing check(s)
    as the source and their remediation text.
  - **`assessment_results.json`**: OSCAL `assessment-results` shape — one
    observation per executed check (with `relevant-evidence` where captured)
    and one finding per technically-assessed control with a
    `satisfied`/`not-satisfied` target, cross-linked to its observations.

## 11. CLI

```
castellan fetch                          # download + cache NIST OSCAL content (one-time)
castellan categorize SYSTEM.yaml         # print FIPS-199 categorization + selected baseline
castellan ssp generate SYSTEM.yaml [-o OUTDIR]
                                         # writes ssp.md + ssp.json
castellan scan [--out OUTDIR] [--json]   # runs host checks, prints rich table of results
castellan report SYSTEM.yaml [-o OUTDIR] # full flow: categorize -> select -> scan ->
                                         #   map -> compliance_report.md + poam + oscal
castellan checks list                    # list all implemented checks and their mapped controls
```

- Every command exits non-zero on error with a clear message. `--help` works
  at every level.
- `report` is the headline command: one invocation produces the whole
  evidence package.

## 12. Output artifacts

`castellan report examples/sample_system.yaml -o out/` produces: `ssp.md`,
`ssp.json`, `compliance_report.md`, `poam.md`, `poam.json`,
`assessment_results.json`. The artifact set committed under
`examples/output/` was generated on a real Ubuntu host (8 pass / 5 fail /
1 error / 6 not-applicable check outcomes; 11 of 287 moderate-baseline
controls technically assessable; 6 open POA&M items), so a genuine result is
visible without running anything.

## 13. Provenance and future work

OSCAL filenames and document shapes were verified against the live
`usnistgov/oscal-content` repository (and its published SSP example) rather
than assumed, and the control ids used in the mapping were validated
programmatically against the catalog and the moderate baseline before being
committed. The committed sample output was captured from a real Ubuntu host
rather than mocked.

Potential future work: a FastAPI dashboard, OpenSCAP integration as an
alternate scan backend, multiple OS profiles, and validation of emitted
OSCAL against NIST's official validator.

## 14. Testing & quality

- 208 tests cover the categorization logic, baseline resolution, every check
  (via fixtures), the mapping and status computation, report counts and
  OSCAL shapes, the CLI (via Typer's `CliRunner` with the host and catalog
  patched at the module boundary), and the `LinuxHost` implementation.
  Coverage is 97%; CI enforces a ≥80% gate.
- Most tests are fixture-based unit tests; integration tests that validate
  against the real cached NIST content auto-skip when it is absent (as in
  CI).
- `ruff` and `mypy --strict` pass clean.
- The CI workflow runs lint, type-check, and tests on every push, on Python
  3.11 and 3.12.
- No secrets, no network in tests, no host mutation anywhere in the codebase.

## 15. Capabilities

- `pip install -e .` then `castellan --help` works; all subcommands are
  documented.
- `castellan categorize examples/sample_system.yaml` prints the CIA values,
  the high-water-mark overall categorization, and the selected baseline.
- `castellan ssp generate` emits an `ssp.md` whose control set exactly
  matches the selected 800-53B baseline (287 controls for moderate), plus a
  structurally faithful OSCAL `ssp.json`.
- `castellan scan` runs 20 read-only checks on a Linux host and prints a
  status table; a failing or erroring check never aborts the run.
- Every check maps to at least one real 800-53 control;
  `castellan checks list` shows the mapping.
- `castellan report` produces the full artifact set in §12, with control
  statuses computed honestly (unmapped controls are `not_assessed`, never
  auto-passed).
- CI is green with coverage ≥80%; the README shows a real sample run with
  committed example output.

## 16. Design philosophy

- **Honesty over impressive-looking pass rates.** A report that truthfully
  says "45.5% of assessable controls pass, 6 POA&M items open" is far more
  credible than one that claims full compliance — and credibility is the
  entire point of a compliance tool. This is why unmapped controls are never
  auto-passed, why evidence-free outcomes (`not_applicable`, `error`) don't
  count toward pass or fail, and why the committed sample output includes
  its failures.
- **Mirror real OSCAL, don't guess.** Where OSCAL structure was in doubt,
  the implementation fetched and inspected NIST's published examples and
  mirrored their shape.
- **Engineering hygiene is part of the tool.** Strict typing,
  fixture-based tests, CI gates, and a README with a real sample run are not
  an afterthought — a compliance tool nobody trusts the build of is a
  compliance tool nobody trusts. The README leads with what RMF is, what the
  tool does in one sentence, an architecture diagram, and a genuine sample
  run.
