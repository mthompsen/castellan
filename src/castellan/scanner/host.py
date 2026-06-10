"""Host access interface for scanner checks.

Checks read host state exclusively through the :class:`Host` protocol, which
keeps every check read-only by construction and lets tests substitute an
in-memory fake. :class:`LinuxHost` is the production implementation; its
paths and semantics (uid 0 = root, systemd service queries) are Linux-only.
"""

from __future__ import annotations

import os
import stat as stat_module
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class FileStat:
    """Permission bits (e.g. ``0o640``) and ownership of a file."""

    mode: int
    uid: int
    gid: int


class Host(Protocol):
    """Read-only view of a host. All scanner checks go through this."""

    def read_text(self, path: str) -> str:
        """Return a file's text. Raises FileNotFoundError if absent."""
        ...

    def exists(self, path: str) -> bool:
        """Whether a path exists."""
        ...

    def stat(self, path: str) -> FileStat | None:
        """Permissions/ownership of a path, or None if it does not exist."""
        ...

    def iter_files(self, path: str, limit: int) -> Iterator[tuple[str, FileStat]]:
        """Yield up to *limit* regular files under *path* (recursive)."""
        ...

    def service_active(self, service: str) -> bool | None:
        """Whether a systemd service is active; None if undeterminable."""
        ...


class LinuxHost:
    """Production Host implementation reading the live local Linux system."""

    def read_text(self, path: str) -> str:
        return Path(path).read_text(encoding="utf-8", errors="replace")

    def exists(self, path: str) -> bool:
        return Path(path).exists()

    def stat(self, path: str) -> FileStat | None:
        try:
            st = os.stat(path)
        except OSError:
            return None
        return FileStat(mode=stat_module.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)

    def iter_files(self, path: str, limit: int) -> Iterator[tuple[str, FileStat]]:
        count = 0
        for dirpath, _dirnames, filenames in os.walk(path):
            for name in filenames:
                if count >= limit:
                    return
                count += 1
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat_module.S_ISREG(st.st_mode):
                    yield (
                        full,
                        FileStat(
                            mode=stat_module.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid
                        ),
                    )

    def service_active(self, service: str) -> bool | None:
        try:
            proc = subprocess.run(  # read-only query; never mutates the host
                ["systemctl", "is-active", "--quiet", service],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.returncode == 0
