# QSIdentify

[![CI](https://github.com/pgousdal/QSIdentify/actions/workflows/ci.yml/badge.svg)](https://github.com/pgousdal/QSIdentify/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/pgousdal/QSIdentify)](LICENSE)

QSIdentify is a strictly read-only identification, diagnostics, and
electronic-evidence tool for programmable radios. It observes protocol behavior
and reported firmware, records bounded serial evidence, and supports
conservative review of possible hardware, MCU, PCB, and bootloader
relationships without treating firmware strings or marketing names as proof.

## What It Does

- Identifies observable protocol behavior and decoded firmware strings.
- Collects bounded, deterministic serial captures with transport diagnostics.
- Separates adapter echo, framed responses, unknown bytes, incomplete frames,
  and passive bootloader responses.
- Produces sanitized evidence bundles and offline registry analyses.
- Supports review, catalog proposal, audit, and deterministic publication
  workflows.
- Preserves unknown and contradictory evidence instead of guessing.

## What It Does Not Claim

Protocol behavior and a reported firmware string may be directly observed.
Hardware revision, MCU family, PCB revision, flash geometry, marketed model,
and bootloader revision may remain unknown. User declarations, physical
inspection notes, statistical correlations, and catalog inferences are kept
separate from electronic observations and are not silently promoted to proof.

## Safety Boundary

QSIdentify has a strict read-only software boundary:

- It sends only compiled-in, allowlisted read-only identification commands.
- It does not write EEPROM or other radio memory.
- It does not flash, erase, reset, or reboot radios.
- It does not enter firmware-update or bootloader mode.
- It does not accept arbitrary transmit frames.
- Normal operation and all evidence/governance workflows use no network access
  or telemetry.

Passive bootloader messages are classified only when a radio sends them without
being prompted by a bootloader command.

## Supported Drivers

| Driver | Protocol family | Supported model names | Status |
|---|---|---|---|
| `quansheng` | Quansheng framed protocol | UV-K5, UV-K5(8), UV-K6, UV-5R Plus | Built in |

The Quansheng driver is currently the only built-in driver. Model names describe
driver scope, not a claim that every named model has been physically tested.

### Physically Validated Hardware

| Driver | Radio | Reported firmware | Result |
|---|---|---:|---|
| `quansheng` | UV-K5(8) | 2.01.36 | Firmware-identification response validated |

A reported firmware version does not establish MCU family, PCB revision,
marketed model, flash geometry, or bootloader revision.

## Quick Start

Install from a source checkout or a locally built wheel:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

For development, install the test and quality tools as well:

```bash
python -m pip install -e '.[dev]'
```

List ports and perform the simplest identification:

```bash
qsidentify ports
qsidentify identify /dev/ttyUSB0
```

Save a detailed bounded capture when investigating a response:

```bash
qsidentify probe /dev/ttyUSB0 \
  --trace \
  --capture capture.json
```

The package is not currently presented as a PyPI release. Use the checkout,
wheel, or source archive produced by the repository build process.

## Example

A successful observable response looks like this:

```text
QSIdentify <current version>

Driver
  ID:                quansheng

Transport
  Port:              /dev/ttyUSB0
  Baud rate:         38400
  Classification:    framed-response

Protocol
  Frame detected:    yes
  Frame complete:    yes
  Message type:      firmware-identification-response

Radio
  Reported version:  2.01.36
  Detected protocol: Quansheng framed identification response
```

This output intentionally does not claim an exact MCU, PCB, or hardware
revision.

## Core Workflows

### Identify a Radio

```bash
qsidentify ports
qsidentify identify /dev/ttyUSB0
qsidentify probe /dev/ttyUSB0 --trace --capture capture.json
```

### Inspect Evidence

```bash
qsidentify capture-inspect capture.json
qsidentify evidence-report capture.json
qsidentify firmware-advice capture.json --model "UV-K5(8)"
```

Firmware advice is offline catalog guidance. It does not select, download, or
flash firmware.

### Advanced Offline Workflows

The CLI also supports sanitized evidence bundles, registry aggregation,
contribution review, governance reviews, catalog proposals, audit history, and
publication verification. Start with `qsidentify --help` and the documentation
index below rather than treating the full CLI as one undifferentiated command
list.

## Evidence Model

Captures preserve bounded transport observations in deterministic JSON. Sanitized
bundles can be compared and imported into an offline registry without treating
repeated captures from one physical radio as independent devices.

The governance lifecycle is explicit:

`Observed -> Sanitized -> Imported -> Reviewed -> Correlated -> Candidate -> Approved -> Published`

Reviews, proposals, approvals, and publication records are immutable audit
events. Statistical correlation can produce a candidate discriminator, but it
cannot establish a hardware identity by itself. See
[`docs/evidence-governance.md`](docs/evidence-governance.md).

## Documentation

See [`docs/README.md`](docs/README.md) for the documentation index.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy src
pytest
python -m compileall -q src tests
python -m build
git diff --check
```

Tests use sanitized fixtures and fake serial connections. No physical radio is
required. Driver changes must preserve the command inventory and the
read-only boundary.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before changing protocol, transport,
capture, evidence, catalog, or governance code. Hardware observations should
follow [`docs/hardware-reporting.md`](docs/hardware-reporting.md), and captures
must be sanitized before publication.

## License

QSIdentify is licensed under [GPL-3.0-or-later](LICENSE).
