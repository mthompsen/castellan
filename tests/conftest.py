"""Shared test infrastructure: an in-memory Host implementation.

FakeHost satisfies the castellan.scanner.host.Host protocol so scanner tests
run against fixture data on any OS, never the real machine.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from castellan.scanner.host import FileStat

HOST_FIXTURES = Path(__file__).parent / "fixtures" / "host"


def fixture_text(name: str) -> str:
    return (HOST_FIXTURES / name).read_text(encoding="utf-8")


class FakeHost:
    """In-memory Host: files by path, explicit stats, service states, walk trees."""

    def __init__(
        self,
        files: dict[str, str] | None = None,
        stats: dict[str, FileStat] | None = None,
        services: dict[str, bool | None] | None = None,
        trees: dict[str, list[tuple[str, FileStat]]] | None = None,
        unreadable: set[str] | None = None,
    ) -> None:
        self.files = files or {}
        self.stats = stats or {}
        self.services = services or {}
        self.trees = trees or {}
        self.unreadable = unreadable or set()

    def read_text(self, path: str) -> str:
        if path in self.unreadable:
            raise PermissionError(path)
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def exists(self, path: str) -> bool:
        return path in self.files or path in self.stats or path in self.trees

    def stat(self, path: str) -> FileStat | None:
        if path in self.stats:
            return self.stats[path]
        if path in self.files:
            return FileStat(mode=0o644, uid=0, gid=0)
        return None

    def iter_files(self, path: str, limit: int) -> Iterator[tuple[str, FileStat]]:
        yield from self.trees.get(path, [])[:limit]

    def service_active(self, service: str) -> bool | None:
        return self.services.get(service)
