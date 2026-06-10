"""Discover and run all registered checks.

One misbehaving check must never abort a scan: exceptions escaping a check
are caught per-check and recorded as ``outcome="error"``.
"""

from __future__ import annotations

from collections.abc import Sequence

from castellan.models import CheckResult
from castellan.scanner.base import Check
from castellan.scanner.checks import accounts, files, logs, services, ssh, updates
from castellan.scanner.host import Host

ALL_CHECKS: tuple[type[Check], ...] = (
    *ssh.CHECKS,
    *accounts.CHECKS,
    *files.CHECKS,
    *services.CHECKS,
    *logs.CHECKS,
    *updates.CHECKS,
)


def run_all(host: Host, checks: Sequence[type[Check]] | None = None) -> list[CheckResult]:
    """Run every registered check against *host*, collecting all results."""
    results: list[CheckResult] = []
    for check_class in ALL_CHECKS if checks is None else checks:
        check = check_class(host)
        try:
            results.append(check.run())
        except Exception as exc:  # one bad check must never crash the run
            results.append(
                CheckResult(
                    check_id=check.check_id,
                    title=check.title,
                    outcome="error",
                    detail=f"check raised {type(exc).__name__}: {exc}",
                    remediation=check.remediation,
                )
            )
    return results
