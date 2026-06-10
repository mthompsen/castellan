"""CLI tests via Typer's CliRunner.

Catalog loading and host scanning are patched at the cli module boundary so
these tests run offline on any OS (CI has no data/oscal cache and no Linux
host state).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from castellan import cli
from castellan.models import Control
from castellan.scanner.checks import ssh
from conftest import FakeHost, fixture_text

runner = CliRunner()

EXAMPLES = Path(__file__).parent.parent / "examples"


def mini_controls(baseline: str = "moderate") -> list[Control]:
    return [
        Control(id="ac-6", family="AC", title="Least Privilege", statement="s",
                in_baseline=True),
        Control(id="ia-5", family="IA", title="Authenticator Management", statement="s",
                in_baseline=True),
    ]


@pytest.fixture
def patched_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "load_controls", mini_controls)


@pytest.fixture
def patched_host(monkeypatch: pytest.MonkeyPatch) -> FakeHost:
    fake = FakeHost(files={ssh.SSHD_CONFIG: fixture_text("sshd_config_hardened")})
    monkeypatch.setattr(cli, "LinuxHost", lambda: fake)
    return fake


class TestHelp:
    def test_top_level_help(self) -> None:
        result = runner.invoke(cli.app, ["--help"])
        assert result.exit_code == 0
        for command in ("categorize", "fetch", "scan", "report", "ssp", "checks"):
            assert command in result.output

    @pytest.mark.parametrize(
        "args",
        [["categorize"], ["fetch"], ["scan"], ["report"], ["ssp", "generate"],
         ["checks", "list"]],
    )
    def test_subcommand_help(self, args: list[str]) -> None:
        result = runner.invoke(cli.app, [*args, "--help"])
        assert result.exit_code == 0


class TestCategorize:
    def test_sample_system(self) -> None:
        result = runner.invoke(
            cli.app, ["categorize", str(EXAMPLES / "sample_system.yaml")]
        )
        assert result.exit_code == 0
        assert "moderate" in result.output

    def test_missing_file_exits_nonzero(self) -> None:
        result = runner.invoke(cli.app, ["categorize", "no_such_file.yaml"])
        assert result.exit_code == 1

    def test_invalid_yaml_exits_nonzero(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("name: [unclosed", encoding="utf-8")
        assert runner.invoke(cli.app, ["categorize", str(bad)]).exit_code == 1

    def test_invalid_description_exits_nonzero(self, tmp_path: Path) -> None:
        bad = tmp_path / "incomplete.yaml"
        bad.write_text("name: X\nsystem_id: X-1\ndescription: d\nowner: o\n", encoding="utf-8")
        assert runner.invoke(cli.app, ["categorize", str(bad)]).exit_code == 1


class TestFetch:
    def test_reports_downloads(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        downloaded = [tmp_path / "catalog.json"]
        monkeypatch.setattr(
            cli, "fetch_oscal_content", lambda force=False: downloaded if force else []
        )
        result = runner.invoke(cli.app, ["fetch"])
        assert result.exit_code == 0
        assert "already cached" in result.output
        result = runner.invoke(cli.app, ["fetch", "--force"])
        assert "catalog.json" in result.output

    def test_failure_exits_nonzero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(force: bool = False) -> list[Path]:
            raise RuntimeError("network down")

        monkeypatch.setattr(cli, "fetch_oscal_content", boom)
        assert runner.invoke(cli.app, ["fetch"]).exit_code == 1


class TestScan:
    def test_table_output(self, patched_host: FakeHost) -> None:
        result = runner.invoke(cli.app, ["scan"])
        assert result.exit_code == 0
        assert "Castellan host scan" in result.output

    def test_json_output(self, patched_host: FakeHost) -> None:
        result = runner.invoke(cli.app, ["scan", "--json"])
        assert result.exit_code == 0
        # Off-Linux the platform warning may precede the payload in the
        # captured stream; the JSON itself starts at the first bracket.
        payload = json.loads(result.output[result.output.index("[") :])
        outcomes = {entry["check_id"]: entry["outcome"] for entry in payload}
        assert outcomes["ssh_permit_root_login"] == "pass"

    def test_out_dir_writes_results_file(
        self, patched_host: FakeHost, tmp_path: Path
    ) -> None:
        result = runner.invoke(cli.app, ["scan", "--out", str(tmp_path / "scan")])
        assert result.exit_code == 0
        written = json.loads(
            (tmp_path / "scan" / "scan_results.json").read_text(encoding="utf-8")
        )
        assert len(written) >= 18


class TestSspGenerate:
    def test_writes_artifacts(self, patched_catalog: None, tmp_path: Path) -> None:
        result = runner.invoke(
            cli.app,
            ["ssp", "generate", str(EXAMPLES / "sample_system.yaml"), "-o", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert (tmp_path / "ssp.md").exists()
        assert (tmp_path / "ssp.json").exists()

    def test_missing_oscal_cache_exits_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def missing(baseline: str) -> list[Control]:
            raise FileNotFoundError("run 'castellan fetch' first")

        monkeypatch.setattr(cli, "load_controls", missing)
        result = runner.invoke(
            cli.app,
            ["ssp", "generate", str(EXAMPLES / "sample_system.yaml"), "-o", str(tmp_path)],
        )
        assert result.exit_code == 1


class TestChecksList:
    def test_lists_all_checks_with_controls(self) -> None:
        result = runner.invoke(cli.app, ["checks", "list"])
        assert result.exit_code == 0
        assert "ssh_permit_root_login" in result.output
        assert "UNMAPPED" not in result.output


class TestReport:
    def test_full_flow_writes_six_artifacts(
        self, patched_catalog: None, patched_host: FakeHost, tmp_path: Path
    ) -> None:
        result = runner.invoke(
            cli.app,
            ["report", str(EXAMPLES / "sample_system.yaml"), "-o", str(tmp_path)],
        )
        assert result.exit_code == 0
        for name in (
            "ssp.md",
            "ssp.json",
            "compliance_report.md",
            "poam.md",
            "poam.json",
            "assessment_results.json",
        ):
            assert (tmp_path / name).exists(), name

    def test_summary_reflects_assessments(
        self, patched_catalog: None, patched_host: FakeHost, tmp_path: Path
    ) -> None:
        # Hardened SSH fixture: ac-6 gets a passing root-login check ->
        # implemented; ia-5 gets pass (empty passwords) + fail (login.defs
        # absent has no result; password checks N/A)... so assert via files.
        result = runner.invoke(
            cli.app,
            ["report", str(EXAMPLES / "sample_system.yaml"), "-o", str(tmp_path)],
        )
        assert result.exit_code == 0
        report_md = (tmp_path / "compliance_report.md").read_text(encoding="utf-8")
        assert "# Compliance Report: Eastport Benefits Portal" in report_md
        ssp_md = (tmp_path / "ssp.md").read_text(encoding="utf-8")
        assert "**Implementation status:** implemented" in ssp_md
