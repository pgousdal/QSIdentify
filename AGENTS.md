# AGENTS.md

## Project purpose

QSIdentify is a read-only diagnostic utility for identifying Quansheng radios,
firmware strings, protocol families and bootloader responses.

Safety is more important than broad device support.

## Non-negotiable rules

1. Never add EEPROM write support.
2. Never add firmware write, erase or reset support.
3. Never transmit arbitrary user-provided frames.
4. Never label inferred hardware as definitively identified.
5. Preserve unknown responses as raw evidence.
6. Keep captures deterministic and human-readable.
7. Every transmit command must have an explicit safety classification.
8. Tests must not require physical radio hardware.

## Architecture

- `cli.py` — command-line interface only
- `ports.py` — serial-port discovery and metadata
- `probe.py` — orchestration of safe probes
- `transport.py` — bounded serial I/O
- `protocol/commands.py` — allowlisted outbound commands
- `protocol/decoder.py` — pure decoding and classification
- `models.py` — immutable report and capture models
- `capture.py` — deterministic JSON serialization
- `doctor.py` — local environment checks
- `drivers/base.py` — stable immutable driver interface
- `drivers/registry.py` — deterministic compiled-in driver registry
- `drivers/quansheng/` — Quansheng protocol, commands, catalogs and advisory
- `advisory.py`, `catalog.py`, `protocol/` — backwards-compatible import shims

Protocol decoding should remain side-effect free.

M0.1 framing lives in `protocol/frame.py`. Logical commands must be encoded by
the codec before transport; decoders must inspect decoded payloads, never raw
protected frame bytes.

M0.2 stream analysis lives in `protocol/stream.py`. Read-chunk boundaries are
transport evidence only. Exact transmit echoes must be excluded from radio
responses, and variable unframed bytes must remain unidentified evidence.

M1.2 electronic evidence analysis lives in `evidence.py`. Candidate
discriminators are experimental and only `verified-discriminator` records may
contribute to an automatic hardware identity.

M1.3 offline aggregation lives in `evidence_registry.py`; deterministic archive
review lives in `contribution.py`. Registries and contribution packages must not
modify production catalogs or promote statistical correlation to verified identity.

M0.3 advisory analysis is offline only. Firmware strings and marketed model
names never establish a hardware revision or MCU. User declarations and local
catalog inferences must remain visibly distinct from electronically observed
evidence.

M1.0 drivers never perform serial I/O. They return allowlisted commands and
purely interpret transport evidence supplied by core orchestration. Runtime
discovery, entry points, dynamic external imports and plugin downloads are
forbidden.

M1.1 fixtures under `tests/fixtures` are sanitized, provenance-labeled and
manifest-hashed. Package, driver API, driver implementation, capture schema and
catalog versions remain separate contracts.

## Coding requirements

- Python 3.11+
- full type annotations
- dataclasses for domain models
- deterministic JSON output
- no broad exception swallowing
- bounded reads and explicit timeouts
- no import-time hardware access
- no hidden network access or telemetry
- no logging of usernames or unrelated device paths

## Testing

Every protocol change requires:

- a byte-level unit test
- a malformed-input test
- a deterministic capture test
- confirmation that no new write-capable command was introduced

Run:

```bash
pytest
ruff check .
mypy src
python -m compileall -q src tests
```

## Identification language

Use:

- `reported_version`
- `detected_protocol`
- `inferred_family`
- `confidence`
- `evidence`

Avoid claims such as `hardware_model` unless the protocol supplies a verified
hardware identifier.
