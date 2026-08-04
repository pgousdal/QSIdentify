from __future__ import annotations

import platform
import sys
from dataclasses import dataclass

import serial

from .ports import list_serial_ports


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str


def run_checks() -> tuple[DoctorCheck, ...]:
    ports = list_serial_ports()
    return (
        DoctorCheck("Python", sys.version_info >= (3, 11), platform.python_version()),
        DoctorCheck("pyserial", True, serial.VERSION),
        DoctorCheck(
            "Serial ports",
            bool(ports),
            f"{len(ports)} port(s) found" if ports else "No serial ports found",
        ),
        DoctorCheck("Safety mode", True, "Read-only command allowlist enabled"),
    )
