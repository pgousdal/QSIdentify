# Read-only command inventory

The packaged `command_inventory.json` is the canonical reviewed inventory.
Every entry records purpose, safety class, request and response types, evidence
targets, allowlist status, and provenance. Unknown commands are unsafe by
default.

Version 1.2 has one runtime transmit entry: Quansheng `0x0514`, the existing
`identify-handshake`, classified `identification-read`. No safe bootloader or
capability request has been established, so those categories are explicitly
unavailable. Write, reset, firmware, calibration, arbitrary, and undocumented
commands cannot enter an executable probe.

Use `qsidentify command-list` and `qsidentify command-info 0x0514` to inspect
the inventory offline.
