"""Logging posture checks (syslog service presence, log file permissions)."""

from __future__ import annotations

from castellan.models import CheckResult
from castellan.scanner.base import Check

SENSITIVE_LOGS = ("/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages")


class SyslogServiceActive(Check):
    check_id = "log_syslog_active"
    title = "A system logging service is running"
    remediation = (
        "Enable a logging service: 'systemctl enable --now rsyslog' or ensure "
        "systemd-journald is running."
    )

    def run(self) -> CheckResult:
        states = {
            name: self.host.service_active(name) for name in ("rsyslog", "systemd-journald")
        }
        if all(state is None for state in states.values()):
            return self.not_applicable("systemd is not available; cannot query service state")
        active = [name for name, state in states.items() if state]
        if active:
            return self.passed(
                f"Logging service active: {', '.join(active)}",
                evidence=f"systemctl is-active {active[0]}",
            )
        return self.failed("Neither rsyslog nor systemd-journald is active")


class LogFilePermissions(Check):
    check_id = "log_file_permissions"
    title = "Sensitive log files are not world-readable"
    remediation = (
        "Run 'chmod o-rwx FILE' on each listed log and ensure log rotation preserves "
        "restrictive modes (e.g. 'create 0640 syslog adm' in logrotate config)."
    )

    def run(self) -> CheckResult:
        present = {path: self.host.stat(path) for path in SENSITIVE_LOGS}
        existing = {path: st for path, st in present.items() if st is not None}
        if not existing:
            return self.not_applicable(
                f"None of the inspected logs exist: {', '.join(SENSITIVE_LOGS)}"
            )
        offenders = [
            f"{path} (mode={oct(st.mode)})"
            for path, st in existing.items()
            if st.mode & 0o007
        ]
        if offenders:
            return self.failed(
                f"World-accessible log file(s): {', '.join(offenders)}",
                evidence=", ".join(offenders),
            )
        return self.passed(
            f"Inspected logs are not world-accessible: {', '.join(existing)}"
        )


CHECKS: tuple[type[Check], ...] = (
    SyslogServiceActive,
    LogFilePermissions,
)
