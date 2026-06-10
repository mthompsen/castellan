"""Filesystem permission checks (/etc/shadow, /etc/passwd, world-writable files)."""

from __future__ import annotations

from castellan.models import CheckResult
from castellan.scanner.base import Check

# Bounded world-writable search: these trees, this many files at most.
SYSTEM_DIRS = ("/etc", "/usr/local/bin", "/usr/local/sbin")
WALK_LIMIT = 5000
_MAX_LISTED = 10


def _format_stat(mode: int, uid: int, gid: int) -> str:
    return f"mode={oct(mode)} uid={uid} gid={gid}"


class FilePermissionsCheck(Check):
    """Base for single-file permission checks: owner must be root and the
    mode must not exceed ``max_mode``. N/A when the file is absent."""

    path: str
    max_mode: int

    def run(self) -> CheckResult:
        st = self.host.stat(self.path)
        if st is None:
            return self.not_applicable(f"{self.path} not present on this host")
        evidence = _format_stat(st.mode, st.uid, st.gid)
        problems = []
        if st.uid != 0:
            problems.append(f"owned by uid {st.uid} instead of root")
        if st.mode & ~self.max_mode:
            problems.append(f"mode {oct(st.mode)} exceeds {oct(self.max_mode)}")
        if problems:
            return self.failed(f"{self.path} is {' and '.join(problems)}", evidence=evidence)
        return self.passed(
            f"{self.path} is root-owned with mode {oct(st.mode)}", evidence=evidence
        )


class ShadowPermissions(FilePermissionsCheck):
    check_id = "fs_shadow_permissions"
    title = "/etc/shadow is root-owned and not world-accessible"
    remediation = "Run 'chown root:shadow /etc/shadow && chmod 0640 /etc/shadow'."
    path = "/etc/shadow"
    max_mode = 0o640


class PasswdPermissions(FilePermissionsCheck):
    check_id = "fs_passwd_permissions"
    title = "/etc/passwd is root-owned and not writable by others"
    remediation = "Run 'chown root:root /etc/passwd && chmod 0644 /etc/passwd'."
    path = "/etc/passwd"
    max_mode = 0o644


class NoWorldWritableFiles(Check):
    check_id = "fs_no_world_writable"
    title = "No world-writable files in system directories"
    remediation = (
        "Remove the world-writable bit ('chmod o-w FILE') from each listed file after "
        "confirming nothing depends on it."
    )

    def run(self) -> CheckResult:
        searched = [path for path in SYSTEM_DIRS if self.host.exists(path)]
        if not searched:
            return self.not_applicable(
                f"None of the searched directories exist: {', '.join(SYSTEM_DIRS)}"
            )
        offenders = []
        budget = WALK_LIMIT
        for directory in searched:
            for file_path, st in self.host.iter_files(directory, budget):
                budget -= 1
                if st.mode & 0o002:
                    offenders.append(file_path)
            if budget <= 0:
                break
        if offenders:
            listed = ", ".join(offenders[:_MAX_LISTED])
            suffix = f" (+{len(offenders) - _MAX_LISTED} more)" if (
                len(offenders) > _MAX_LISTED
            ) else ""
            return self.failed(
                f"{len(offenders)} world-writable file(s) in {', '.join(searched)}: "
                f"{listed}{suffix}",
                evidence=listed,
            )
        return self.passed(
            f"No world-writable files found in {', '.join(searched)} "
            f"(searched up to {WALK_LIMIT} files)"
        )


CHECKS: tuple[type[Check], ...] = (
    ShadowPermissions,
    PasswdPermissions,
    NoWorldWritableFiles,
)
