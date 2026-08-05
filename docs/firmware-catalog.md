# Offline firmware catalog

`src/qsidentify/data/firmware_catalog.json` is schema version 1, catalog version
`2026.08`. It is human-reviewed metadata, not automatically discovered truth.
Each entry records a project name, supported MCU and revision IDs, explicitly
unsupported revisions, CHIRP-driver requirements, risk notes and source
provenance.

The catalog contains no firmware binaries or direct binary URLs. QSIdentify
does not scrape projects at runtime and performs no network access. Repository
names and compatibility information may become stale, so users must consult a
project's own current documentation before flashing anything.

`qsidentify firmware-catalog-validate` checks schema versions, unique IDs,
known MCU and revision identifiers, provenance, project/revision uniqueness,
status/risk enums, binary URL/path exclusion and deterministic ordering.
`firmware-list` and `hardware-list` display metadata without accessing a radio.
