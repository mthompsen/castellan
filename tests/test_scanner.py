"""Scanner tests: every check exercised via fixture data, never the real host."""

from __future__ import annotations

import pytest

from castellan.models import CheckResult
from castellan.scanner.base import Check
from castellan.scanner.checks import accounts, files, logs, services, ssh, updates
from castellan.scanner.host import FileStat
from castellan.scanner.runner import ALL_CHECKS, run_all
from conftest import FakeHost, fixture_text


def run_one(check_class: type[Check], host: FakeHost) -> CheckResult:
    return check_class(host).run()


def hardened_ssh_host() -> FakeHost:
    return FakeHost(files={ssh.SSHD_CONFIG: fixture_text("sshd_config_hardened")})


def weak_ssh_host() -> FakeHost:
    return FakeHost(files={ssh.SSHD_CONFIG: fixture_text("sshd_config_weak")})


class TestSshChecks:
    @pytest.mark.parametrize("check_class", ssh.CHECKS)
    def test_hardened_config_passes_all(self, check_class: type[Check]) -> None:
        result = run_one(check_class, hardened_ssh_host())
        assert result.outcome == "pass", result.detail

    @pytest.mark.parametrize("check_class", ssh.CHECKS)
    def test_weak_config_fails_all(self, check_class: type[Check]) -> None:
        result = run_one(check_class, weak_ssh_host())
        assert result.outcome == "fail", result.detail

    @pytest.mark.parametrize("check_class", ssh.CHECKS)
    def test_missing_sshd_config_is_not_applicable(self, check_class: type[Check]) -> None:
        result = run_one(check_class, FakeHost())
        assert result.outcome == "not_applicable"

    def test_match_block_directives_are_ignored(self) -> None:
        # The weak fixture sets PermitRootLogin no inside a Match block;
        # the global 'yes' must win.
        options = ssh.parse_sshd_config(fixture_text("sshd_config_weak"))
        assert options["permitrootlogin"] == "yes"
        assert "1" in options["protocol"].split(",")

    def test_first_occurrence_wins(self) -> None:
        options = ssh.parse_sshd_config("MaxAuthTries 3\nMaxAuthTries 99\n")
        assert options["maxauthtries"] == "3"

    def test_unset_root_login_fails_with_default_explanation(self) -> None:
        host = FakeHost(files={ssh.SSHD_CONFIG: "Port 22\n"})
        result = run_one(ssh.SshPermitRootLogin, host)
        assert result.outcome == "fail"
        assert "prohibit-password" in result.detail

    def test_unset_ciphers_pass_with_modern_defaults(self) -> None:
        host = FakeHost(files={ssh.SSHD_CONFIG: "PermitRootLogin no\n"})
        assert run_one(ssh.SshWeakCrypto, host).outcome == "pass"

    def test_unset_empty_passwords_passes_by_default(self) -> None:
        host = FakeHost(files={ssh.SSHD_CONFIG: "Port 22\n"})
        assert run_one(ssh.SshPermitEmptyPasswords, host).outcome == "pass"

    def test_non_numeric_interval_fails(self) -> None:
        host = FakeHost(files={ssh.SSHD_CONFIG: "ClientAliveInterval abc\n"})
        assert run_one(ssh.SshClientAliveInterval, host).outcome == "fail"

    def test_oversized_interval_fails(self) -> None:
        host = FakeHost(files={ssh.SSHD_CONFIG: "ClientAliveInterval 86400\n"})
        assert run_one(ssh.SshClientAliveInterval, host).outcome == "fail"


class TestAccountChecks:
    def test_hardened_login_defs_passes(self) -> None:
        host = FakeHost(files={accounts.LOGIN_DEFS: fixture_text("login_defs_hardened")})
        assert run_one(accounts.PasswordMaxDays, host).outcome == "pass"
        assert run_one(accounts.PasswordWarnAge, host).outcome == "pass"

    def test_weak_login_defs_fails(self) -> None:
        host = FakeHost(files={accounts.LOGIN_DEFS: fixture_text("login_defs_weak")})
        assert run_one(accounts.PasswordMaxDays, host).outcome == "fail"
        assert run_one(accounts.PasswordWarnAge, host).outcome == "fail"

    def test_missing_login_defs_is_not_applicable(self) -> None:
        assert run_one(accounts.PasswordMaxDays, FakeHost()).outcome == "not_applicable"

    def test_min_length_prefers_pwquality(self) -> None:
        host = FakeHost(
            files={
                accounts.PWQUALITY_CONF: fixture_text("pwquality_conf"),
                accounts.LOGIN_DEFS: fixture_text("login_defs_weak"),
            }
        )
        result = run_one(accounts.PasswordMinLength, host)
        assert result.outcome == "pass"
        assert "pwquality" in str(result.evidence)

    def test_min_length_falls_back_to_login_defs(self) -> None:
        host = FakeHost(files={accounts.LOGIN_DEFS: fixture_text("login_defs_hardened")})
        result = run_one(accounts.PasswordMinLength, host)
        assert result.outcome == "pass"
        assert "PASS_MIN_LEN" in str(result.evidence)

    def test_min_length_unconfigured_fails(self) -> None:
        host = FakeHost(files={accounts.LOGIN_DEFS: fixture_text("login_defs_weak")})
        assert run_one(accounts.PasswordMinLength, host).outcome == "fail"

    def test_min_length_no_files_not_applicable(self) -> None:
        assert run_one(accounts.PasswordMinLength, FakeHost()).outcome == "not_applicable"

    def test_clean_passwd_passes(self) -> None:
        host = FakeHost(files={accounts.PASSWD: fixture_text("passwd_clean")})
        assert run_one(accounts.NoDuplicateUidZero, host).outcome == "pass"

    def test_duplicate_uid0_fails_and_names_account(self) -> None:
        host = FakeHost(files={accounts.PASSWD: fixture_text("passwd_duplicate_uid0")})
        result = run_one(accounts.NoDuplicateUidZero, host)
        assert result.outcome == "fail"
        assert "toor" in result.detail

    def test_clean_shadow_passes(self) -> None:
        host = FakeHost(files={accounts.SHADOW: fixture_text("shadow_clean")})
        assert run_one(accounts.NoEmptyPasswords, host).outcome == "pass"

    def test_empty_password_fails_and_names_account(self) -> None:
        host = FakeHost(files={accounts.SHADOW: fixture_text("shadow_empty_password")})
        result = run_one(accounts.NoEmptyPasswords, host)
        assert result.outcome == "fail"
        assert "kiosk" in result.detail

    def test_unreadable_shadow_is_error_with_root_hint(self) -> None:
        host = FakeHost(unreadable={accounts.SHADOW})
        host.files[accounts.SHADOW] = ""  # exists but unreadable
        result = run_one(accounts.NoEmptyPasswords, host)
        assert result.outcome == "error"
        assert "root" in result.detail


class TestFileChecks:
    def test_correct_shadow_perms_pass(self) -> None:
        host = FakeHost(stats={"/etc/shadow": FileStat(mode=0o640, uid=0, gid=42)})
        assert run_one(files.ShadowPermissions, host).outcome == "pass"

    def test_world_readable_shadow_fails(self) -> None:
        host = FakeHost(stats={"/etc/shadow": FileStat(mode=0o644, uid=0, gid=0)})
        result = run_one(files.ShadowPermissions, host)
        assert result.outcome == "fail"
        assert "0o644" in result.detail

    def test_non_root_owned_shadow_fails(self) -> None:
        host = FakeHost(stats={"/etc/shadow": FileStat(mode=0o600, uid=1000, gid=0)})
        result = run_one(files.ShadowPermissions, host)
        assert result.outcome == "fail"
        assert "uid 1000" in result.detail

    def test_missing_shadow_is_not_applicable(self) -> None:
        assert run_one(files.ShadowPermissions, FakeHost()).outcome == "not_applicable"

    def test_correct_passwd_perms_pass(self) -> None:
        host = FakeHost(stats={"/etc/passwd": FileStat(mode=0o644, uid=0, gid=0)})
        assert run_one(files.PasswdPermissions, host).outcome == "pass"

    def test_group_writable_passwd_fails(self) -> None:
        host = FakeHost(stats={"/etc/passwd": FileStat(mode=0o664, uid=0, gid=0)})
        assert run_one(files.PasswdPermissions, host).outcome == "fail"

    def test_no_world_writable_files_passes(self) -> None:
        host = FakeHost(
            trees={
                "/etc": [
                    ("/etc/hosts", FileStat(mode=0o644, uid=0, gid=0)),
                    ("/etc/fstab", FileStat(mode=0o644, uid=0, gid=0)),
                ]
            }
        )
        assert run_one(files.NoWorldWritableFiles, host).outcome == "pass"

    def test_world_writable_file_fails_and_is_listed(self) -> None:
        host = FakeHost(
            trees={
                "/etc": [
                    ("/etc/hosts", FileStat(mode=0o644, uid=0, gid=0)),
                    ("/etc/evil.conf", FileStat(mode=0o666, uid=0, gid=0)),
                ]
            }
        )
        result = run_one(files.NoWorldWritableFiles, host)
        assert result.outcome == "fail"
        assert "/etc/evil.conf" in result.detail

    def test_no_system_dirs_is_not_applicable(self) -> None:
        assert run_one(files.NoWorldWritableFiles, FakeHost()).outcome == "not_applicable"


class TestServiceChecks:
    def test_auditd_active_passes(self) -> None:
        host = FakeHost(services={"auditd": True})
        assert run_one(services.AuditdActive, host).outcome == "pass"

    def test_auditd_inactive_fails(self) -> None:
        host = FakeHost(services={"auditd": False})
        assert run_one(services.AuditdActive, host).outcome == "fail"

    def test_no_systemd_is_not_applicable(self) -> None:
        assert run_one(services.AuditdActive, FakeHost()).outcome == "not_applicable"

    @pytest.mark.parametrize("firewall", services.FIREWALL_SERVICES)
    def test_any_active_firewall_passes(self, firewall: str) -> None:
        states: dict[str, bool | None] = dict.fromkeys(services.FIREWALL_SERVICES, False)
        states[firewall] = True
        result = run_one(services.FirewallActive, FakeHost(services=states))
        assert result.outcome == "pass"
        assert firewall in result.detail

    def test_no_firewall_fails(self) -> None:
        states: dict[str, bool | None] = dict.fromkeys(services.FIREWALL_SERVICES, False)
        assert run_one(services.FirewallActive, FakeHost(services=states)).outcome == "fail"

    def test_firewall_without_systemd_not_applicable(self) -> None:
        assert run_one(services.FirewallActive, FakeHost()).outcome == "not_applicable"

    def test_strict_crontab_passes(self) -> None:
        host = FakeHost(stats={"/etc/crontab": FileStat(mode=0o600, uid=0, gid=0)})
        assert run_one(services.CrontabPermissions, host).outcome == "pass"

    def test_world_readable_crontab_fails(self) -> None:
        host = FakeHost(stats={"/etc/crontab": FileStat(mode=0o644, uid=0, gid=0)})
        assert run_one(services.CrontabPermissions, host).outcome == "fail"

    def test_missing_crontab_is_not_applicable(self) -> None:
        assert run_one(services.CrontabPermissions, FakeHost()).outcome == "not_applicable"


class TestLogChecks:
    def test_rsyslog_active_passes(self) -> None:
        host = FakeHost(services={"rsyslog": True, "systemd-journald": False})
        assert run_one(logs.SyslogServiceActive, host).outcome == "pass"

    def test_journald_alone_passes(self) -> None:
        host = FakeHost(services={"rsyslog": False, "systemd-journald": True})
        assert run_one(logs.SyslogServiceActive, host).outcome == "pass"

    def test_no_logging_service_fails(self) -> None:
        host = FakeHost(services={"rsyslog": False, "systemd-journald": False})
        assert run_one(logs.SyslogServiceActive, host).outcome == "fail"

    def test_restrictive_log_perms_pass(self) -> None:
        host = FakeHost(
            stats={
                "/var/log/auth.log": FileStat(mode=0o640, uid=0, gid=4),
                "/var/log/syslog": FileStat(mode=0o640, uid=0, gid=4),
            }
        )
        assert run_one(logs.LogFilePermissions, host).outcome == "pass"

    def test_world_readable_log_fails(self) -> None:
        host = FakeHost(stats={"/var/log/auth.log": FileStat(mode=0o644, uid=0, gid=4)})
        result = run_one(logs.LogFilePermissions, host)
        assert result.outcome == "fail"
        assert "/var/log/auth.log" in result.detail

    def test_no_logs_present_is_not_applicable(self) -> None:
        assert run_one(logs.LogFilePermissions, FakeHost()).outcome == "not_applicable"


class TestUpdateChecks:
    def test_apt_unattended_upgrades_enabled_passes(self) -> None:
        host = FakeHost(
            files={
                "/etc/apt": "",
                updates.APT_AUTO_UPGRADES: fixture_text("apt_auto_upgrades_enabled"),
            }
        )
        assert run_one(updates.AutomaticUpdates, host).outcome == "pass"

    def test_apt_unattended_upgrades_disabled_fails(self) -> None:
        host = FakeHost(
            files={
                "/etc/apt": "",
                updates.APT_AUTO_UPGRADES: fixture_text("apt_auto_upgrades_disabled"),
            }
        )
        assert run_one(updates.AutomaticUpdates, host).outcome == "fail"

    def test_apt_without_config_file_fails(self) -> None:
        host = FakeHost(files={"/etc/apt": ""})
        assert run_one(updates.AutomaticUpdates, host).outcome == "fail"

    def test_dnf_automatic_with_timer_passes(self) -> None:
        host = FakeHost(
            files={"/etc/dnf": "", updates.DNF_AUTOMATIC_CONF: ""},
            services={"dnf-automatic.timer": True},
        )
        assert run_one(updates.AutomaticUpdates, host).outcome == "pass"

    def test_dnf_automatic_without_timer_fails(self) -> None:
        host = FakeHost(
            files={"/etc/dnf": "", updates.DNF_AUTOMATIC_CONF: ""},
            services={"dnf-automatic.timer": False},
        )
        assert run_one(updates.AutomaticUpdates, host).outcome == "fail"

    def test_unknown_package_manager_is_not_applicable(self) -> None:
        assert run_one(updates.AutomaticUpdates, FakeHost()).outcome == "not_applicable"


class _ExplodingCheck(Check):
    check_id = "test_exploding"
    title = "A check that always raises"
    remediation = "n/a"

    def run(self) -> CheckResult:
        raise RuntimeError("boom")


class TestRunner:
    def test_at_least_18_checks_registered(self) -> None:
        assert len(ALL_CHECKS) >= 18

    def test_check_ids_are_unique(self) -> None:
        ids = [check.check_id for check in ALL_CHECKS]
        assert len(set(ids)) == len(ids)

    def test_every_check_has_remediation_and_title(self) -> None:
        for check in ALL_CHECKS:
            assert check.title
            assert check.remediation

    def test_run_all_returns_one_result_per_check(self) -> None:
        results = run_all(FakeHost())
        assert len(results) == len(ALL_CHECKS)
        assert [r.check_id for r in results] == [c.check_id for c in ALL_CHECKS]

    def test_exploding_check_becomes_error_not_crash(self) -> None:
        results = run_all(FakeHost(), checks=[_ExplodingCheck, ssh.SshPermitRootLogin])
        assert len(results) == 2
        assert results[0].outcome == "error"
        assert "RuntimeError" in results[0].detail
        assert results[1].outcome == "not_applicable"

    def test_empty_host_yields_no_passes_or_fails_for_file_checks(self) -> None:
        # A bare host (no files, no systemd) must produce only honest outcomes.
        results = run_all(FakeHost())
        assert {r.outcome for r in results} <= {"not_applicable", "fail"}
