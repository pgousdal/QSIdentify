from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Confidence(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    value: str
    source: str


@dataclass(frozen=True, slots=True)
class PortInfo:
    device: str
    description: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    serial_number: str | None = None
    vid: int | None = None
    pid: int | None = None

    @property
    def vid_pid(self) -> str | None:
        if self.vid is None or self.pid is None:
            return None
        return f"{self.vid:04x}:{self.pid:04x}"


@dataclass(frozen=True, slots=True)
class Exchange:
    request: bytes
    response: bytes


@dataclass(frozen=True, slots=True)
class ProbeReport:
    schema_version: int
    qsidentify_version: str
    port: PortInfo
    baud_rate: int
    operating_mode: str
    response_received: bool
    reported_version: str | None = None
    detected_protocol: str | None = None
    inferred_family: str | None = None
    confidence: Confidence = Confidence.NONE
    evidence: tuple[Evidence, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    report: "ProbeReport"
    exchange: Exchange


@dataclass(frozen=True, slots=True)
class Capture:
    schema_version: int
    created_utc: str
    port: PortInfo
    baud_rate: int
    request_hex: str
    response_hex: str
    report: ProbeReport
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
