# QSIdentify

**Read-only identification and diagnostics for Quansheng radios.**

QSIdentify probes a radio over a serial programming cable and records the
evidence returned by the device. It is intentionally conservative:

> QSIdentify reports evidence, not guesses.

The M0 release never writes EEPROM, never writes firmware and never switches a
radio into flash mode.

## Status

M0 repository foundation.

Implemented:

- serial-port discovery
- USB/serial metadata display
- read-only probe framework
- normal-mode handshake transport
- raw response capture
- JSON reports
- offline capture decoding
- diagnostic command
- simulated protocol tests
- explicit safety policy

The initial protocol codec deliberately treats unknown frames as evidence
instead of pretending to identify unsupported radios.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Commands

```bash
qsidentify ports
qsidentify probe /dev/ttyUSB0
qsidentify probe --auto
qsidentify probe /dev/ttyUSB0 --trace
qsidentify probe /dev/ttyUSB0 --json
qsidentify decode capture.json
qsidentify doctor
```

## Examples

List candidate programming ports:

```bash
qsidentify ports
```

Probe one port:

```bash
qsidentify probe /dev/ttyUSB0
```

Probe and save a capture:

```bash
qsidentify probe /dev/ttyUSB0 --trace --capture radio.json
```

Decode an existing capture without connecting to a radio:

```bash
qsidentify decode radio.json
```

## Safety model

M0 permits only:

- opening a serial port
- sending the configured identification handshake
- reading the response
- recording local metadata and byte streams

M0 forbids:

- EEPROM writes
- firmware writes
- erase commands
- reset commands
- automatic bootloader entry
- arbitrary user-supplied transmit frames

Every outbound byte sequence must be declared in
`src/qsidentify/protocol/commands.py` with a safety classification.

## Identification model

QSIdentify separates facts into three levels:

- **reported** — text or values returned directly by the radio
- **detected** — protocol or transport behavior observed by QSIdentify
- **inferred** — a model or hardware-family estimate based on evidence

An inference always carries a confidence level and supporting evidence.

## Current limitation

Quansheng firmware strings are not guaranteed to uniquely identify hardware.
Custom firmware can change the reported string, and related models can share
protocols. M0 therefore favors captures and transparent evidence.

## Development

```bash
pytest
ruff check .
mypy src
python -m compileall -q src tests
```

## License

GPL-3.0-or-later.
