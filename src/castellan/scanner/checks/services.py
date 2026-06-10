"""Service posture checks (auditd, firewall, cron permissions)."""

from __future__ import annotations

from castellan.models import CheckResult
from castellan.scanner.base import Check
from castellan.scanner.checks.files import FilePermissionsCheck

FIREWALL_SERVICES = ("ufw", "firewalld", "nftables")


class AuditdActive(Check):
    check_id = "svc_auditd_active"
    title = "Linux audit daemon (auditd) is running"
    remediation = (
        "Install and enable the audit daemon: 'apt install auditd && systemctl enable "
        "--now auditd' (or the dnf equivalent)."
    )

    def run(self) -> CheckResult:
        active = self.host.service_active("auditd")
        if active is None:
            return self.not_applicable("systemd is not available; cannot query service state")
        if active:
            return self.passed("auditd service is active", evidence="systemctl is-active auditd")
        return self.failed("auditd service is not active; system calls are not being audited")


class FirewallActive(Check):
    check_id = "svc_firewall_active"
    title = "A host firewall is active"
    remediation = (
        "Enable a host firewall, e.g. 'ufw enable' (Ubuntu) or 'systemctl enable --now "
        "firewalld' (RHEL), with a default-deny inbound policy."
    )

    def run(self) -> CheckResult:
        states = {name: self.host.service_active(name) for name in FIREWALL_SERVICES}
        if all(state is None for state in states.values()):
            return self.not_applicable("systemd is not available; cannot query service state")
        active = [name for name, state in states.items() if state]
        if active:
            return self.passed(
                f"Firewall service active: {', '.join(active)}",
                evidence=f"systemctl is-active {active[0]}",
            )
        return self.failed(
            f"No firewall service is active (checked {', '.join(FIREWALL_SERVICES)})"
        )


class CrontabPermissions(FilePermissionsCheck):
    check_id = "svc_crontab_permissions"
    title = "/etc/crontab is root-owned and not readable by others"
    remediation = "Run 'chown root:root /etc/crontab && chmod 0600 /etc/crontab'."
    path = "/etc/crontab"
    max_mode = 0o600


CHECKS: tuple[type[Check], ...] = (
    AuditdActive,
    FirewallActive,
    CrontabPermissions,
)
