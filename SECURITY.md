# Security Policy

QSIdentify handles serial devices and evidence that may contain identifying
metadata. Security reports should cover both software security and radio
safety.

## Supported Versions

The `main` branch is the actively maintained development line. Check the
changelog and repository tags for release-specific support information.

## Reporting A Vulnerability

Use GitHub's private vulnerability reporting or Security Advisory workflow in
the repository when it is enabled. Do not publish exploit details, unsafe radio
commands, raw captures, USB serials, hostnames, or private paths in a public
issue.

If private reporting is unavailable, open a minimal public issue requesting a
private contact path and do not include sensitive details. Maintainers should
enable private vulnerability reporting and document the selected route in the
repository settings.

## In Scope

- archive traversal, duplicate-member, executable-member, or checksum bypasses;
- unsafe command inventory or arbitrary-frame transmission;
- unintended EEPROM, firmware, reset, reboot, or bootloader operations;
- capture sanitization leaks;
- network or telemetry behavior introduced into normal operation;
- dependency or packaging issues that compromise users.

Reports about contribution archives and publication packages should include the
sanitized archive structure, not private evidence contents.

## Safety Boundary

Do not attempt destructive testing on a radio. QSIdentify is intentionally
read-only and does not accept unsafe diagnostic commands as a security-testing
mechanism.
