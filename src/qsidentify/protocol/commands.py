from __future__ import annotations

from qsidentify.models import Command, SafetyClass

# Logical command 0x0514: passive normal-mode firmware/version query.
IDENTIFY_HANDSHAKE = Command(
    name="identify-handshake",
    payload=bytes.fromhex("14 05 04 00 6a 39 57 64"),
    safety=SafetyClass.READ_ONLY,
    description="Read-only Quansheng normal-mode firmware identification query",
)

ALLOWLIST: tuple[Command, ...] = (IDENTIFY_HANDSHAKE,)

__all__ = ["ALLOWLIST", "IDENTIFY_HANDSHAKE"]
