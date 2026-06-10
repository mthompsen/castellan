"""Account and password policy checks (/etc/login.defs, /etc/passwd, /etc/shadow)."""

from __future__ import annotations

import re

from castellan.models import CheckResult
from castellan.scanner.base import Check

LOGIN_DEFS = "/etc/login.defs"
PASSWD = "/etc/passwd"
SHADOW = "/etc/shadow"
PWQUALITY_CONF = "/etc/security/pwquality.conf"


def parse_kv_config(text: str) -> dict[str, str]:
    """Parse KEY VALUE (or KEY = VALUE) lines, ignoring comments."""
    options: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[ \t=]+", line, maxsplit=1)
        if len(parts) == 2:
            options.setdefault(parts[0].upper(), parts[1].strip())
    return options


class LoginDefsCheck(Check):
    """Base for checks evaluating /etc/login.defs; N/A when absent."""

    def run(self) -> CheckResult:
        try:
            text = self.host.read_text(LOGIN_DEFS)
        except FileNotFoundError:
            return self.not_applicable(f"{LOGIN_DEFS} not present on this host")
        return self.evaluate(parse_kv_config(text))

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        raise NotImplementedError


class PasswordMaxDays(LoginDefsCheck):
    check_id = "accounts_password_max_days"
    title = "Password maximum age is limited"
    remediation = f"Set 'PASS_MAX_DAYS 365' (or lower) in {LOGIN_DEFS}."

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        value = options.get("PASS_MAX_DAYS")
        if value is None:
            return self.failed("PASS_MAX_DAYS is not set; passwords never expire by default")
        try:
            days = int(value)
        except ValueError:
            return self.failed(
                f"PASS_MAX_DAYS has a non-numeric value '{value}'",
                evidence=f"PASS_MAX_DAYS {value}",
            )
        if 1 <= days <= 365:
            return self.passed(
                f"Passwords expire after {days} days", evidence=f"PASS_MAX_DAYS {value}"
            )
        return self.failed(
            f"PASS_MAX_DAYS is {days}; should be 365 or less",
            evidence=f"PASS_MAX_DAYS {value}",
        )


class PasswordMinLength(Check):
    check_id = "accounts_password_min_length"
    title = "Password minimum length policy is enforced"
    remediation = (
        f"Set 'minlen = 14' in {PWQUALITY_CONF} (libpwquality), or 'PASS_MIN_LEN 14' "
        f"in {LOGIN_DEFS} on systems without pam_pwquality."
    )

    def run(self) -> CheckResult:
        try:
            options = parse_kv_config(self.host.read_text(PWQUALITY_CONF))
            value, source = options.get("MINLEN"), f"{PWQUALITY_CONF} minlen"
        except FileNotFoundError:
            try:
                options = parse_kv_config(self.host.read_text(LOGIN_DEFS))
                value, source = options.get("PASS_MIN_LEN"), f"{LOGIN_DEFS} PASS_MIN_LEN"
            except FileNotFoundError:
                return self.not_applicable(
                    f"Neither {PWQUALITY_CONF} nor {LOGIN_DEFS} present on this host"
                )
        if value is None:
            return self.failed(f"No minimum password length configured (checked {source})")
        try:
            length = int(value)
        except ValueError:
            return self.failed(f"{source} has a non-numeric value '{value}'")
        if length >= 14:
            return self.passed(
                f"Minimum password length is {length}", evidence=f"{source} = {value}"
            )
        return self.failed(
            f"Minimum password length is {length}; should be 14 or more",
            evidence=f"{source} = {value}",
        )


class PasswordWarnAge(LoginDefsCheck):
    check_id = "accounts_password_warn_age"
    title = "Users are warned before password expiry"
    remediation = f"Set 'PASS_WARN_AGE 7' (or higher) in {LOGIN_DEFS}."

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        value = options.get("PASS_WARN_AGE")
        if value is None:
            return self.failed("PASS_WARN_AGE is not set")
        try:
            days = int(value)
        except ValueError:
            return self.failed(
                f"PASS_WARN_AGE has a non-numeric value '{value}'",
                evidence=f"PASS_WARN_AGE {value}",
            )
        if days >= 7:
            return self.passed(
                f"Users are warned {days} days before expiry", evidence=f"PASS_WARN_AGE {value}"
            )
        return self.failed(
            f"PASS_WARN_AGE is {days}; should be 7 or more", evidence=f"PASS_WARN_AGE {value}"
        )


class NoDuplicateUidZero(Check):
    check_id = "accounts_no_duplicate_uid0"
    title = "Only root has UID 0"
    remediation = (
        "Remove or re-uid any non-root account with UID 0; investigate how it was created."
    )

    def run(self) -> CheckResult:
        try:
            text = self.host.read_text(PASSWD)
        except FileNotFoundError:
            return self.not_applicable(f"{PASSWD} not present on this host")
        offenders = []
        for line in text.splitlines():
            fields = line.split(":")
            if len(fields) >= 3 and fields[2] == "0" and fields[0] != "root":
                offenders.append(fields[0])
        if offenders:
            return self.failed(
                f"Non-root account(s) with UID 0: {', '.join(offenders)}",
                evidence=", ".join(offenders),
            )
        return self.passed("root is the only UID 0 account")


class NoEmptyPasswords(Check):
    check_id = "accounts_no_empty_passwords"
    title = "No account has an empty password"
    remediation = (
        "Lock affected accounts ('passwd -l USER') or set a strong password immediately."
    )

    def run(self) -> CheckResult:
        try:
            text = self.host.read_text(SHADOW)
        except FileNotFoundError:
            return self.not_applicable(f"{SHADOW} not present on this host")
        except PermissionError:
            return self.error(f"{SHADOW} is not readable; run the scan as root")
        offenders = []
        for line in text.splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[1] == "":
                offenders.append(fields[0])
        if offenders:
            return self.failed(
                f"Account(s) with empty password: {', '.join(offenders)}",
                evidence=", ".join(offenders),
            )
        return self.passed("Every account has a password hash or is locked")


CHECKS: tuple[type[Check], ...] = (
    PasswordMaxDays,
    PasswordMinLength,
    PasswordWarnAge,
    NoDuplicateUidZero,
    NoEmptyPasswords,
)
