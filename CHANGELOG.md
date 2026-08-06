# Changelog

## Unreleased — M2.0 governance layer

- add immutable evidence lifecycle transitions with chained audit history
- add structured review records, blind review views and configurable thresholds
- add explicit catalog proposals, approvals and regression certification
- add deterministic, checksummed publication ZIP verification
- add offline governance CLI commands and public governance API

## 1.3.0 - 2026-08-05

- add deterministic schema-v1 offline evidence registries with immutable records
- separate bundle, content, fingerprint, device, capture and probe-run identities
- aggregate repeated observations without treating captures as independent devices
- add conservative discriminator correlation policy and blocking conflict codes
- add deterministic, traversal-safe contribution ZIP creation and review
- require explicit approval for atomic contribution imports and preserve audit events

## 1.2.0 - 2026-08-05

- add a packaged inventory that keeps undocumented or unsafe commands unavailable
- add bounded named evidence probes using only the existing identification command
- add deterministic stability masks and content-addressed electronic fingerprints
- add candidate discriminator metadata without automatic hardware mappings
- add offline evidence reporting, comparison, and sanitized contribution bundles
- keep MCU, PCB revision, and hardware revision unresolved without verified evidence

## 1.1.0 - 2026-08-05

- add sanitized hardware regression captures and fixture manifest
- add capture sanitize, inspect and validation workflows
- define driver API version 1 and stable JSON/release/audit contracts
- verify packaged catalogs and isolated wheel/sdist installation

## 1.0.0 - 2026-08-05

- introduce a stable, immutable driver interface and deterministic built-in registry
- move Quansheng protocol, commands, catalogs and advisory logic into its driver
- make transport analysis driver-injected and keep drivers free of serial I/O
- add driver-aware capture schema v3 with v1/v2 loading compatibility
- add `drivers`, `driver-info` and the public `identify()` Python API

## 0.3.0 - 2026-08-05

- add a conservative offline firmware compatibility advisory
- add canonical legacy/V1, V2/PY32F030 and V3/PY32F071 hardware records
- add a versioned, human-reviewable firmware project catalog
- keep protocol observations, user declarations and database inferences separate
- reject conflicting revision, PCB and MCU declarations without recommendations
- add firmware advice, firmware list, hardware list and catalog validation commands

## 0.2.0 - 2026-08-04

- collect complete bounded RX streams until idle or total timeout
- record timestamped serial read chunks and explicit DTR/RTS state
- detect complete, repeated and partial transmit echoes without treating them as responses
- classify null-only, unframed binary, incomplete and invalid framed streams
- scan past malformed candidates for later valid Quansheng frames
- add passive `monitor`, controlled `matrix` and offline `compare` commands
- upgrade captures to schema v2 while retaining schema-v1 loading
- document physical UV-K5(8)/CH340 observations without inferring a new protocol

## 0.1.1 - 2026-08-04

- encode the read-only identify payload in a validated Quansheng frame
- add CRC-16/XMODEM and repeating-XOR byte fixtures
- distinguish verified CRC from accepted legacy `ff ff` responses
- replace generic serial reads with bounded frame-aware transport
- decode text only from deobfuscated payloads
- recognize passive `18 05` bootloader evidence
- consolidate immutable domain models and explicit serialization
- validate and atomically write deterministic capture schema v1
- harden CLI errors, JSON-only output, trace details, and doctor checks
- expand hardware-free protocol, malformed-input, transport, capture, and safety tests
