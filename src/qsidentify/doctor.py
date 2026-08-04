from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

import serial

from . import __version__
from .models import SafetyClass
from .ports import list_serial_ports
from .protocol.commands import ALLOWLIST
from .protocol.frame import decode_frame, encode_frame


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str


def run_checks(*, capture_directory: Path | None = None) -> tuple[DoctorCheck, ...]:
    ports = list_serial_ports()
    unsafe = [command.name for command in ALLOWLIST if command.safety is not SafetyClass.READ_ONLY]
    test_payload = bytes.fromhex("14 05 04 00 6a 39 57 64")
    protocol_ok = decode_frame(encode_frame(test_payload)).payload == test_payload
    inaccessible = [port.device for port in ports if not os.access(port.device, os.R_OK | os.W_OK)]
    directory = capture_directory or Path.cwd()
    return (
        DoctorCheck("Python", sys.version_info >= (3, 11), platform.python_version()),
        DoctorCheck("Package version", __version__ == "0.1.1", __version__),
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
        DoctorCheck(
            "Capture directory",
            directory.is_dir() and os.access(directory, os.W_OK),
            "Writable" if directory.is_dir() and os.access(directory, os.W_OK) else "Not writable",
        ),
    )
