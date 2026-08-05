# QSIdentify

**Read-only identification and diagnostics for Quansheng radios.**

QSIdentify 1.1.0 sends one allowlisted, read-only identification query and
records the complete bounded serial stream. It separates adapter echo, framed
responses, null bytes, incomplete candidates and unknown binary evidence
without claiming that a firmware string proves a hardware revision.

M0.3 adds an entirely offline firmware compatibility advisory. It compares
captures and explicit user-supplied hardware details with a curated local
catalog. It never downloads, modifies, selects, packages, or flashes firmware.

M1.0 introduces a stable built-in driver architecture. Core transport, capture,
CLI and public API code are radio-independent; the Quansheng codec, commands,
decoder, catalogs and advisory implementation live in the `quansheng` driver.

## M0.2 status

M0 incorrectly sent the logical identification payload as if it were a complete
serial command, read the response in one generic operation, and searched framed
and obfuscated bytes for text. M0.1 adds the Quansheng frame codec, bounded
frame-aware transport, payload-only response classification, schema-validated
captures, and stable CLI errors.

M0.2 follows physical UV-K5(8) observations where CH340 cables sometimes echoed
the exact transmit frame or returned variable null/unframed bytes. These are
transport observations, not evidence of a new Quansheng protocol. The codec
remains fixture-validated; real radios may expose additional variants.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Commands

```bash
qsidentify ports
qsidentify --version
qsidentify drivers
qsidentify driver-info quansheng
qsidentify probe /dev/ttyUSB0
qsidentify probe /dev/ttyUSB0 --driver quansheng
qsidentify probe --auto
qsidentify probe /dev/ttyUSB0 --trace
qsidentify probe /dev/ttyUSB0 --json
qsidentify probe /dev/ttyUSB0 --capture capture.json
qsidentify monitor /dev/ttyUSB0 --duration 5 --dtr off --rts off --trace
qsidentify matrix /dev/ttyUSB0 --capture-dir captures/matrix
qsidentify decode capture.json
qsidentify compare capture1.json capture2.json
qsidentify firmware-advice capture.json --model "UV-K5(8)"
qsidentify firmware-list
qsidentify hardware-list
qsidentify firmware-catalog-validate
qsidentify doctor
```

Example summary:

```text
QSIdentify 1.1.0

Transport
  Port:              /dev/ttyUSB0
  Baud rate:         38400
  Request bytes:     16

Protocol
  Frame detected:    yes
  Frame complete:    yes
  Checksum:          valid
  Message type:      firmware-identification-response

Radio
  Reported version:  V1.0
  Inferred family:   -
  Confidence:        low
```

Use `--trace` to display logical and encoded transmit bytes, raw receive bytes,
each timestamped serial read, combined RX bytes, echoes, candidates, decoded
payload and checksums. `monitor` never transmits. `matrix` runs at most twelve
read-only probes across explicit DTR/RTS and settle-delay combinations.

## Safety boundary

QSIdentify may discover ports, open the selected port, transmit the compiled-in
identification query, read a bounded response, and save local evidence. It has
no arbitrary-frame option and no EEPROM write, firmware write, erase, reset,
reboot, or bootloader-entry command. Bootloader messages are recognized only
when a radio sends one without prompting.

## Identification model

- **reported**: a string returned in the decoded radio payload
- **detected**: observed framing or message behavior
- **inferred**: a conservative protocol/firmware-family interpretation

`V1.0`, custom-firmware names, and similar strings can be changed or shared
between products. They are not verified hardware identifiers.

## Development

```bash
pytest
ruff check .
mypy src
python -m compileall -q src tests
python -m build
git diff --check
```

All tests use generated fixtures and fake serial connections; no radio is
required. See `docs/protocol.md`, `docs/protocol-safety.md`, and
`docs/capture-format.md`. Transport evidence and physical observations are in
`docs/transport-diagnostics.md`. Firmware advisory limitations are documented
in `docs/firmware-advisory.md`, `docs/hardware-evidence.md`, and
`docs/firmware-catalog.md`.

The stable Python entry point hides transport internals:

```python
from qsidentify import identify

result = identify("/dev/ttyUSB0")
print(result.report.detected_protocol)
```

## License

GPL-3.0-or-later.
