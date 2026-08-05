from __future__ import annotations

import os
import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import serial

from . import __version__
from .capture import CAPTURE_SCHEMA_VERSION
from .models import SafetyClass
from .ports import list_serial_ports
from .protocol.commands import ALLOWLIST
from .protocol.frame import decode_frame, encode_frame
from .protocol.stream import analyze_stream


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str
    offline: bool = True


def run_checks(*, capture_directory: Path | None = None) -> tuple[DoctorCheck, ...]:
    ports = list_serial_ports()
    unsafe = [command.name for command in ALLOWLIST if command.safety is not SafetyClass.READ_ONLY]
    test_payload = bytes.fromhex("14 05 04 00 6a 39 57 64")
    protocol_ok = decode_frame(encode_frame(test_payload)).payload == test_payload
    encoded = encode_frame(test_payload)
    echo_ok = analyze_stream(encoded, encoded).classification.value == "echo-only"
    null_ok = analyze_stream(b"\x00\x00", encoded).classification.value == "null-byte-response"
    inaccessible = [port.device for port in ports if not os.access(port.device, os.R_OK | os.W_OK)]
    directory = capture_directory or Path.cwd()
    return (
        DoctorCheck("Python", sys.version_info >= (3, 11), platform.python_version()),
        DoctorCheck("Package version", __version__ == "0.2.0", __version__),
        DoctorCheck("pyserial", bool(serial.VERSION), serial.VERSION),
        DoctorCheck(
            "Serial-port discovery",
            True,
            f"{len(ports)} candidate port(s) found" if ports else "No serial ports found",
        ),
        DoctorCheck(
            "Candidate access",
            not inaccessible,
            (
                "Accessible or no candidates"
                if not inaccessible
                else f"Inaccessible: {len(inaccessible)}"
            ),
        ),
        DoctorCheck(
            "Command allowlist",
            bool(ALLOWLIST) and not unsafe,
            f"{len(ALLOWLIST)} read-only command(s)" if not unsafe else "Unsafe command detected",
        ),
        DoctorCheck("Protocol self-test", protocol_ok, "Frame codec round trip"),
        DoctorCheck("Monotonic timer", callable(time.monotonic), "Available"),
        DoctorCheck("Echo detector", echo_ok, "Offline exact-frame fixture"),
        DoctorCheck("Null classifier", null_ok, "Offline zero-byte fixture"),
        DoctorCheck(
            "Capture schema", CAPTURE_SCHEMA_VERSION == 2, f"Schema {CAPTURE_SCHEMA_VERSION}"
        ),
        DoctorCheck(
            "Capture directory",
            directory.is_dir() and os.access(directory, os.W_OK),
            "Writable" if directory.is_dir() and os.access(directory, os.W_OK) else "Not writable",
        ),
    )
