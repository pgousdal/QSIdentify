from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SafetyClass(StrEnum):
    READ_ONLY = "read-only"


@dataclass(frozen=True, slots=True)
class Command:
    name: str
    payload: bytes
    safety: SafetyClass
    description: str


# Placeholder allowlisted identification handshake for the M0 transport.
# Replace only after validating against primary protocol documentation and
# recorded hardware captures. It remains isolated so reviews can audit every
# outbound byte sequence.
IDENTIFY_HANDSHAKE = Command(
    name="identify-handshake",
    payload=bytes.fromhex("14 05 04 00 6a 39 57 64"),
    safety=SafetyClass.READ_ONLY,
    description="Quansheng-compatible normal-mode identification handshake",
)

ALLOWLIST = (IDENTIFY_HANDSHAKE,)
