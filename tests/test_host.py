"""Tests for the LinuxHost implementation.

File operations are exercised against pytest tmp directories (portable to any
OS); systemctl queries are exercised through a stubbed subprocess.run, so no
test depends on the machine actually running systemd.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from castellan.scanner.host import FileStat, LinuxHost


@pytest.fixture
def host() -> LinuxHost:
    return LinuxHost()


class TestFileOperations:
    def test_read_text(self, host: LinuxHost, tmp_path: Path) -> None:
        target = tmp_path / "config"
        target.write_text("PermitRootLogin no\n", encoding="utf-8")
        assert host.read_text(str(target)) == "PermitRootLogin no\n"

    def test_read_missing_raises_file_not_found(self, host: LinuxHost, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            host.read_text(str(tmp_path / "absent"))

    def test_exists(self, host: LinuxHost, tmp_path: Path) -> None:
        present = tmp_path / "present"
        present.write_text("x", encoding="utf-8")
        assert host.exists(str(present))
        assert not host.exists(str(tmp_path / "absent"))

    def test_stat_returns_permission_bits_and_ownership(
        self, host: LinuxHost, tmp_path: Path
    ) -> None:
        target = tmp_path / "file"
        target.write_text("x", encoding="utf-8")
        st = host.stat(str(target))
        assert isinstance(st, FileStat)
        assert 0 <= st.mode <= 0o7777
        assert isinstance(st.uid, int)
        assert isinstance(st.gid, int)

    def test_stat_missing_returns_none(self, host: LinuxHost, tmp_path: Path) -> None:
        assert host.stat(str(tmp_path / "absent")) is None

    def test_iter_files_walks_recursively(self, host: LinuxHost, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("a", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.txt").write_text("b", encoding="utf-8")
        found = {Path(p).name for p, _ in host.iter_files(str(tmp_path), limit=10)}
        assert found == {"a.txt", "b.txt"}

    def test_iter_files_respects_limit(self, host: LinuxHost, tmp_path: Path) -> None:
        for i in range(5):
            (tmp_path / f"f{i}.txt").write_text("x", encoding="utf-8")
        assert len(list(host.iter_files(str(tmp_path), limit=3))) == 3

    def test_iter_files_yields_stats(self, host: LinuxHost, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("x", encoding="utf-8")
        ((_, st),) = list(host.iter_files(str(tmp_path), limit=10))
        assert isinstance(st, FileStat)


class _StubProcess:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


class TestServiceActive:
    def _patch_run(
        self, monkeypatch: pytest.MonkeyPatch, *, returncode: int | None = None,
        raises: Exception | None = None
    ) -> dict[str, Any]:
        seen: dict[str, Any] = {}

        def fake_run(args: list[str], **kwargs: Any) -> _StubProcess:
            seen["args"] = args
            if raises is not None:
                raise raises
            assert returncode is not None
            return _StubProcess(returncode)

        monkeypatch.setattr("castellan.scanner.host.subprocess.run", fake_run)
        return seen

    def test_active_service_returns_true(
        self, host: LinuxHost, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = self._patch_run(monkeypatch, returncode=0)
        assert host.service_active("auditd") is True
        assert seen["args"] == ["systemctl", "is-active", "--quiet", "auditd"]

    def test_inactive_service_returns_false(
        self, host: LinuxHost, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_run(monkeypatch, returncode=3)
        assert host.service_active("auditd") is False

    def test_missing_systemctl_returns_none(
        self, host: LinuxHost, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_run(monkeypatch, raises=FileNotFoundError("systemctl"))
        assert host.service_active("auditd") is None

    def test_timeout_returns_none(
        self, host: LinuxHost, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_run(
            monkeypatch, raises=subprocess.TimeoutExpired(cmd="systemctl", timeout=10)
        )
        assert host.service_active("auditd") is None
