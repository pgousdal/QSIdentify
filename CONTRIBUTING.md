# Contributing

QSIdentify is a read-only diagnostic and evidence project. Contributions must
preserve the strict safety boundary and the distinction between observed
electronic evidence, physical inspection, statistical correlation, reviewer
conclusions, and catalog records.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run the complete local quality gate:

```bash
ruff check .
ruff format --check .
mypy src
pytest
python -m compileall -q src tests
python -m build
git diff --check
```

Tests must not require a physical radio, network runtime access, telemetry, or
secrets.

## Safety Requirements

- Do not add EEPROM, firmware write, erase, reset, reboot, or bootloader-entry
  support.
- Do not add arbitrary user-provided serial frames.
- Every transmitted command must be compiled in, allowlisted, and explicitly
  classified as read-only.
- Keep protocol decoding pure and driver serial-I/O-free.
- Preserve unknown responses as raw evidence.
- Do not turn firmware strings or marketing names into hardware proof.

## Evidence And Fixtures

Sanitize captures before sharing them. Do not commit hostnames, usernames,
filesystem paths, USB serial numbers, or unrelated device metadata. Fixture
changes must include provenance and deterministic manifest updates where the
fixture corpus requires them.

Separate user declarations, physical inspections, electronic observations,
statistical candidates, reviews, proposals, and approved publications. Do not
modify production catalogs outside the approved governance workflow.

## Driver And Catalog Changes

New drivers must implement the stable driver interface and remain compiled in;
runtime plugin discovery and downloads are not supported. Add byte-level,
malformed-input, deterministic-capture, and command-safety tests for protocol
changes. Hardware mappings require reproducible evidence and explicit review;
candidate discriminators are not verified identities.

## Pull Requests

Explain the safety impact, evidence provenance, tests run, and any unresolved
limitations. Keep commits focused and use imperative, descriptive messages.
Do not include firmware binaries or raw private captures in pull requests.
