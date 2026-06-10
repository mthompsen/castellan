"""Check abstract base class.

Every check declares an id, title, and remediation, and implements
``run() -> CheckResult``. Checks read host state only through the Host
interface and must return ``not_applicable`` (not ``error``) when the thing
they inspect is genuinely absent from the host.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from castellan.models import CheckResult
from castellan.scanner.host import Host


class Check(ABC):
    """One read-only hardening check against a host."""

    check_id: ClassVar[str]
    title: ClassVar[str]
    remediation: ClassVar[str]

    def __init__(self, host: Host) -> None:
        self.host = host

    @abstractmethod
    def run(self) -> CheckResult:
        """Inspect the host and return the outcome."""

    def _result(
        self, outcome: str, detail: str, evidence: str | None = None
    ) -> CheckResult:
        return CheckResult.model_validate(
            {
                "check_id": self.check_id,
                "title": self.title,
                "outcome": outcome,
                "detail": detail,
                "evidence": evidence,
                "remediation": self.remediation,
            }
        )

    def passed(self, detail: str, evidence: str | None = None) -> CheckResult:
        return self._result("pass", detail, evidence)

    def failed(self, detail: str, evidence: str | None = None) -> CheckResult:
        return self._result("fail", detail, evidence)

    def not_applicable(self, detail: str) -> CheckResult:
        return self._result("not_applicable", detail)

    def error(self, detail: str) -> CheckResult:
        return self._result("error", detail)
