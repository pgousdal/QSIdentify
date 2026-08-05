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
from .drivers import default_driver
from .models import SafetyClass
from .ports import list_serial_ports


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str
    offline: bool = True


def run_checks(*, capture_directory: Path | None = None) -> tuple[DoctorCheck, ...]:
    ports = list_serial_ports()
    driver = default_driver()
    commands = driver.supported_commands()
    unsafe = [command.name for command in commands if command.safety is not SafetyClass.READ_ONLY]
    command = driver.identify()
    encoded = driver.encode(command)
    protocol_ok = driver.decode(encoded).frame is not None
    echo_ok = driver.analyze_stream(encoded, encoded).classification.value == "echo-only"
    null_ok = (
        driver.analyze_stream(b"\x00\x00", encoded).classification.value == "null-byte-response"
    )
    inaccessible = [port.device for port in ports if not os.access(port.device, os.R_OK | os.W_OK)]
    directory = capture_directory or Path.cwd()
    return (
        DoctorCheck("Python", sys.version_info >= (3, 11), platform.python_version()),
        DoctorCheck("Package version", __version__ == "1.0.0", __version__),
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
            bool(commands) and not unsafe,
            f"{len(commands)} read-only command(s)" if not unsafe else "Unsafe command detected",
        ),
        DoctorCheck("Protocol self-test", protocol_ok, "Frame codec round trip"),
        DoctorCheck("Monotonic timer", callable(time.monotonic), "Available"),
        DoctorCheck("Echo detector", echo_ok, "Offline exact-frame fixture"),
        DoctorCheck("Null classifier", null_ok, "Offline zero-byte fixture"),
        DoctorCheck(
            "Capture schema", CAPTURE_SCHEMA_VERSION == 3, f"Schema {CAPTURE_SCHEMA_VERSION}"
        ),
        DoctorCheck(
            "Capture directory",
            directory.is_dir() and os.access(directory, os.W_OK),
            "Writable" if directory.is_dir() and os.access(directory, os.W_OK) else "Not writable",
        ),
    )
