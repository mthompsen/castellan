"""Automatic security update checks (best-effort, apt and dnf)."""

from __future__ import annotations

import re

from castellan.models import CheckResult
from castellan.scanner.base import Check

APT_AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
DNF_AUTOMATIC_CONF = "/etc/dnf/automatic.conf"

_APT_ENABLED_RE = re.compile(r'APT::Periodic::Unattended-Upgrade\s+"([^"]*)"')


class AutomaticUpdates(Check):
    check_id = "upd_automatic_updates"
    title = "Automatic security updates are configured"
    remediation = (
        "On Debian/Ubuntu: 'apt install unattended-upgrades && dpkg-reconfigure -plow "
        "unattended-upgrades'. On RHEL/Fedora: 'dnf install dnf-automatic && systemctl "
        "enable --now dnf-automatic.timer'."
    )

    def run(self) -> CheckResult:
        if self.host.exists("/etc/apt"):
            return self._check_apt()
        if self.host.exists("/etc/dnf"):
            return self._check_dnf()
        return self.not_applicable(
            "Neither apt nor dnf detected; automatic-update detection not supported "
            "for this package manager"
        )

    def _check_apt(self) -> CheckResult:
        try:
            text = self.host.read_text(APT_AUTO_UPGRADES)
        except FileNotFoundError:
            return self.failed(
                f"{APT_AUTO_UPGRADES} not present; unattended-upgrades is not configured"
            )
        match = _APT_ENABLED_RE.search(text)
        if match and match.group(1) == "1":
            return self.passed(
                "unattended-upgrades is enabled",
                evidence=f'{APT_AUTO_UPGRADES}: APT::Periodic::Unattended-Upgrade "1"',
            )
        return self.failed(
            f"unattended-upgrades is present but disabled in {APT_AUTO_UPGRADES}",
            evidence=match.group(0) if match else None,
        )

    def _check_dnf(self) -> CheckResult:
        if self.host.exists(DNF_AUTOMATIC_CONF):
            timer = self.host.service_active("dnf-automatic.timer")
            if timer:
                return self.passed(
                    "dnf-automatic is installed and its timer is active",
                    evidence=DNF_AUTOMATIC_CONF,
                )
            return self.failed(
                f"{DNF_AUTOMATIC_CONF} exists but dnf-automatic.timer is not active"
            )
        return self.failed(f"{DNF_AUTOMATIC_CONF} not present; dnf-automatic is not installed")


CHECKS: tuple[type[Check], ...] = (AutomaticUpdates,)
