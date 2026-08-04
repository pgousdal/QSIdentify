from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Confidence(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SafetyClass(StrEnum):
    READ_ONLY = "read-only"


class ChecksumStatus(StrEnum):
    VALID = "valid"
    LEGACY_FF_FF = "accepted-legacy-ff-ff"
    INVALID = "invalid"


class MessageType(StrEnum):
    NO_RESPONSE = "no-response"
    INCOMPLETE_RESPONSE = "incomplete-response"
    INVALID_FRAME = "invalid-frame"
    VALID_UNKNOWN_FRAME = "valid-unknown-frame"
    FIRMWARE_IDENTIFICATION = "firmware-identification-response"
    BOOTLOADER_RESPONSE = "bootloader-response"
    UNKNOWN_SERIAL_RESPONSE = "unknown-serial-response"


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
class Command:
    name: str
    payload: bytes
    safety: SafetyClass
    description: str

    def encoded_frame(self) -> bytes:
        # Local import keeps models independent of protocol implementation details.
        from .protocol.frame import encode_frame

        return encode_frame(self.payload)


@dataclass(frozen=True, slots=True)
class DecodedFrame:
    original: bytes
    payload: bytes
    checksum_received: int | None
    checksum_calculated: int
    checksum_status: ChecksumStatus

    @property
    def checksum_valid(self) -> bool:
        return self.checksum_status is ChecksumStatus.VALID


@dataclass(frozen=True, slots=True)
class DecodedResponse:
    reported_version: str | None
    reported_bootloader_version: str | None
    detected_protocol: str | None
    message_type: MessageType
    inferred_family: str | None
    confidence: Confidence
    evidence: tuple[Evidence, ...]
    warnings: tuple[str, ...]
    frame: DecodedFrame | None = None


@dataclass(frozen=True, slots=True)
class Exchange:
    logical_request: bytes
    transmitted_frame: bytes
    leading_bytes: bytes
    received_frame: bytes
    expected_frame_size: int | None = None
    complete: bool = True

    @property
    def response(self) -> bytes:
        return self.leading_bytes + self.received_frame


@dataclass(frozen=True, slots=True)
class ProbeReport:
    schema_version: int
    qsidentify_version: str
    port: PortInfo
    baud_rate: int
    timeout: float
    operating_mode: str
    response_received: bool
    frame_detected: bool
    frame_complete: bool
    message_type: MessageType
    reported_version: str | None = None
    reported_bootloader_version: str | None = None
    detected_protocol: str | None = None
    inferred_family: str | None = None
    confidence: Confidence = Confidence.NONE
    evidence: tuple[Evidence, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return probe_report_to_dict(self)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    report: ProbeReport
    exchange: Exchange
    decoded: DecodedResponse


@dataclass(frozen=True, slots=True)
class Capture:
    schema_version: int
    created_utc: str
    qsidentify_version: str
    port: PortInfo
    baud_rate: int
    timeout: float
    logical_request_payload_hex: str
    encoded_transmitted_frame_hex: str
    leading_response_bytes_hex: str
    received_frame_hex: str
    decoded_payload_hex: str
    checksum_status: ChecksumStatus | None
    report: ProbeReport
    safety: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return capture_to_dict(self)


def port_to_dict(port: PortInfo) -> dict[str, Any]:
    return {
        "description": port.description,
        "device": port.device,
        "manufacturer": port.manufacturer,
        "pid": port.pid,
        "product": port.product,
        "serial_number": port.serial_number,
        "vid": port.vid,
    }


def evidence_to_dict(evidence: Evidence) -> dict[str, str]:
    return {"kind": evidence.kind, "source": evidence.source, "value": evidence.value}


def probe_report_to_dict(report: ProbeReport) -> dict[str, Any]:
    return {
        "baud_rate": report.baud_rate,
        "confidence": report.confidence.value,
        "detected_protocol": report.detected_protocol,
        "evidence": [evidence_to_dict(item) for item in report.evidence],
        "frame_complete": report.frame_complete,
        "frame_detected": report.frame_detected,
        "inferred_family": report.inferred_family,
        "message_type": report.message_type.value,
        "operating_mode": report.operating_mode,
        "port": port_to_dict(report.port),
        "qsidentify_version": report.qsidentify_version,
        "reported_bootloader_version": report.reported_bootloader_version,
        "reported_version": report.reported_version,
        "response_received": report.response_received,
        "schema_version": report.schema_version,
        "timeout": report.timeout,
        "warnings": list(report.warnings),
    }


def capture_to_dict(capture: Capture) -> dict[str, Any]:
    return {
        "baud_rate": capture.baud_rate,
        "checksum_status": capture.checksum_status.value if capture.checksum_status else None,
        "created_utc": capture.created_utc,
        "decoded_payload_hex": capture.decoded_payload_hex,
        "encoded_transmitted_frame_hex": capture.encoded_transmitted_frame_hex,
        "leading_response_bytes_hex": capture.leading_response_bytes_hex,
        "logical_request_payload_hex": capture.logical_request_payload_hex,
        "port": port_to_dict(capture.port),
        "probe_report": probe_report_to_dict(capture.report),
        "qsidentify_version": capture.qsidentify_version,
        "received_frame_hex": capture.received_frame_hex,
        "safety": dict(capture.safety),
        "schema_version": capture.schema_version,
        "timeout": capture.timeout,
    }
