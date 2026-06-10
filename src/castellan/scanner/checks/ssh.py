"""OpenSSH server hardening checks (/etc/ssh/sshd_config).

Parsing follows sshd semantics: keywords are case-insensitive, the first
occurrence of a keyword wins, and only the global section is considered
(parsing stops at the first ``Match`` block).
"""

from __future__ import annotations

import re
from abc import abstractmethod

from castellan.models import CheckResult
from castellan.scanner.base import Check

SSHD_CONFIG = "/etc/ssh/sshd_config"

_WEAK_CIPHER_MARKERS = ("-cbc", "3des", "arcfour", "blowfish", "cast128")


def parse_sshd_config(text: str) -> dict[str, str]:
    """Parse the global section of an sshd_config into lowercase key -> value."""
    options: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[ \t=]+", line, maxsplit=1)
        if len(parts) != 2:
            continue
        key, value = parts[0].lower(), parts[1].strip().strip('"')
        if key == "match":
            break
        options.setdefault(key, value)
    return options


class SshdConfigCheck(Check):
    """Base for checks that evaluate sshd_config; N/A when no SSH server."""

    def run(self) -> CheckResult:
        try:
            text = self.host.read_text(SSHD_CONFIG)
        except FileNotFoundError:
            return self.not_applicable(f"{SSHD_CONFIG} not present; OpenSSH server not installed")
        return self.evaluate(parse_sshd_config(text))

    @abstractmethod
    def evaluate(self, options: dict[str, str]) -> CheckResult:
        """Judge the parsed global sshd options."""


class SshPermitRootLogin(SshdConfigCheck):
    check_id = "ssh_permit_root_login"
    title = "SSH root login is disabled"
    remediation = f"Set 'PermitRootLogin no' in {SSHD_CONFIG} and restart sshd."

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        value = options.get("permitrootlogin")
        if value == "no":
            return self.passed("PermitRootLogin is 'no'", evidence=f"PermitRootLogin {value}")
        if value is None:
            return self.failed(
                "PermitRootLogin is not set; OpenSSH defaults to 'prohibit-password', "
                "which still permits key-based root login"
            )
        return self.failed(
            f"PermitRootLogin is '{value}', allowing direct root login",
            evidence=f"PermitRootLogin {value}",
        )


class SshPasswordAuthentication(SshdConfigCheck):
    check_id = "ssh_password_authentication"
    title = "SSH password authentication is disabled"
    remediation = (
        f"Set 'PasswordAuthentication no' in {SSHD_CONFIG} (after deploying SSH keys) "
        "and restart sshd."
    )

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        value = options.get("passwordauthentication")
        if value == "no":
            return self.passed(
                "PasswordAuthentication is 'no'; key-based authentication only",
                evidence=f"PasswordAuthentication {value}",
            )
        if value is None:
            return self.failed("PasswordAuthentication is not set; OpenSSH defaults to 'yes'")
        return self.failed(
            "Password authentication is enabled, exposing accounts to password guessing",
            evidence=f"PasswordAuthentication {value}",
        )


class SshWeakCrypto(SshdConfigCheck):
    check_id = "ssh_weak_crypto"
    title = "SSH protocol and ciphers exclude weak algorithms"
    remediation = (
        f"Remove 'Protocol 1' and any CBC/3DES/arcfour ciphers from {SSHD_CONFIG}; "
        "prefer chacha20-poly1305 and aes-gcm cipher suites."
    )

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        protocol = options.get("protocol")
        if protocol is not None and "1" in protocol.split(","):
            return self.failed(
                "Protocol 1 is enabled; SSHv1 is cryptographically broken",
                evidence=f"Protocol {protocol}",
            )
        ciphers = options.get("ciphers")
        if ciphers is None:
            return self.passed(
                "No legacy Protocol directive and no cipher override; modern OpenSSH "
                "defaults exclude weak ciphers"
            )
        weak = [
            cipher
            for cipher in ciphers.split(",")
            if any(marker in cipher.lower() for marker in _WEAK_CIPHER_MARKERS)
        ]
        if weak:
            return self.failed(
                f"Weak ciphers configured: {', '.join(weak)}",
                evidence=f"Ciphers {ciphers}",
            )
        return self.passed("Configured cipher list contains no weak algorithms",
                           evidence=f"Ciphers {ciphers}")


class SshClientAliveInterval(SshdConfigCheck):
    check_id = "ssh_client_alive_interval"
    title = "SSH idle session timeout is configured"
    remediation = (
        f"Set 'ClientAliveInterval 300' (and 'ClientAliveCountMax 3' or lower) in "
        f"{SSHD_CONFIG} and restart sshd."
    )

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        value = options.get("clientaliveinterval")
        if value is None:
            return self.failed("ClientAliveInterval is not set; idle sessions never time out")
        try:
            interval = int(value)
        except ValueError:
            return self.failed(
                f"ClientAliveInterval has a non-numeric value '{value}'",
                evidence=f"ClientAliveInterval {value}",
            )
        if 1 <= interval <= 900:
            return self.passed(
                f"Idle keepalive interval is {interval} seconds",
                evidence=f"ClientAliveInterval {value}",
            )
        if interval == 0:
            return self.failed(
                "ClientAliveInterval is 0; idle sessions never time out",
                evidence=f"ClientAliveInterval {value}",
            )
        return self.failed(
            f"ClientAliveInterval is {interval} seconds; should be 900 or less",
            evidence=f"ClientAliveInterval {value}",
        )


class SshMaxAuthTries(SshdConfigCheck):
    check_id = "ssh_max_auth_tries"
    title = "SSH limits authentication attempts"
    remediation = f"Set 'MaxAuthTries 4' (or lower) in {SSHD_CONFIG} and restart sshd."

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        value = options.get("maxauthtries")
        if value is None:
            return self.failed("MaxAuthTries is not set; OpenSSH defaults to 6")
        try:
            tries = int(value)
        except ValueError:
            return self.failed(
                f"MaxAuthTries has a non-numeric value '{value}'",
                evidence=f"MaxAuthTries {value}",
            )
        if 1 <= tries <= 4:
            return self.passed(
                f"Authentication attempts limited to {tries} per connection",
                evidence=f"MaxAuthTries {value}",
            )
        return self.failed(
            f"MaxAuthTries is {tries}; should be 4 or less",
            evidence=f"MaxAuthTries {value}",
        )


class SshPermitEmptyPasswords(SshdConfigCheck):
    check_id = "ssh_permit_empty_passwords"
    title = "SSH rejects empty passwords"
    remediation = f"Set 'PermitEmptyPasswords no' in {SSHD_CONFIG} and restart sshd."

    def evaluate(self, options: dict[str, str]) -> CheckResult:
        value = options.get("permitemptypasswords")
        if value == "yes":
            return self.failed(
                "PermitEmptyPasswords is 'yes'; accounts with empty passwords can log in",
                evidence=f"PermitEmptyPasswords {value}",
            )
        if value is None:
            return self.passed("PermitEmptyPasswords is not set; OpenSSH defaults to 'no'")
        return self.passed(
            f"PermitEmptyPasswords is '{value}'",
            evidence=f"PermitEmptyPasswords {value}",
        )


CHECKS: tuple[type[Check], ...] = (
    SshPermitRootLogin,
    SshPasswordAuthentication,
    SshWeakCrypto,
    SshClientAliveInterval,
    SshMaxAuthTries,
    SshPermitEmptyPasswords,
)
