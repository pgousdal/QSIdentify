# Firmware compatibility advisory

QSIdentify does not download, select, modify, package, unpack or flash
firmware. The advisory is an offline comparison between a read-only capture,
explicit user declarations and the packaged catalog.

A returned firmware string such as `2.01.36` confirms only the decoded string.
It does not uniquely identify the PCB revision, marketed model or MCU. Likewise,
names such as UV-K5, UV-K5(8), UV-K6 and UV-5R Plus may be shared across
incompatible hardware revisions.

Compatibility states are deliberately narrow:

- `compatible-confirmed` requires reliable independent electronic hardware
  evidence. M0.3 has no such source and does not produce this state.
- `compatible-by-declared-hardware` means the local catalog supports a revision
  or MCU supplied by the user. QSIdentify did not verify that declaration.
- `potentially-compatible` is reserved for future catalog relationships that
  establish a relevant family without establishing the revision. Current
  marketed names are not sufficient.
- `incompatible` means declared hardware contradicts catalog support.
- `unknown` means the exact hardware evidence is insufficient.
- `conflicting-evidence` means declarations disagree; no recommendation is made.

Firmware for the wrong MCU family can make a radio unbootable. Always consult
the selected project's current documentation; the local catalog may be stale.
No firmware should be flashed based on QSIdentify's firmware advisory alone.
