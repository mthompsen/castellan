"""Read-only host hardening scanner.

Checks inspect Linux host state (config files, file permissions, service
status) through the :class:`~castellan.scanner.host.Host` interface and never
modify anything. Tests substitute a fake host built from fixture files, so
the suite runs identically on any OS.
"""
