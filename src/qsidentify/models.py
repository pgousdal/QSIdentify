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
    TRANSMIT_ECHO = "transmit-echo"
    ECHO_ONLY = "echo-only"
    PARTIAL_TRANSMIT_ECHO = "partial-transmit-echo"
    ECHO_FOLLOWED_BY_RESPONSE = "echo-followed-by-response"
    NULL_BYTE_RESPONSE = "null-byte-response"
    UNFRAMED_BINARY_RESPONSE = "unframed-binary-response"


class TransportClassification(StrEnum):
    NO_RESPONSE = "no-response"
    FRAMED_RESPONSE = "framed-response"
    TRANSMIT_ECHO = "transmit-echo"
    ECHO_ONLY = "echo-only"
    PARTIAL_TRANSMIT_ECHO = "partial-transmit-echo"
    ECHO_FOLLOWED_BY_RESPONSE = "echo-followed-by-response"
    NULL_BYTE_RESPONSE = "null-byte-response"
    UNFRAMED_BINARY_RESPONSE = "unframed-binary-response"
    INCOMPLETE_RESPONSE = "incomplete-response"
    INVALID_FRAME = "invalid-frame"


class LineSetting(StrEnum):
    AUTO = "auto"
    ON = "on"
    OFF = "off"


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
        from .drivers import default_driver

        return default_driver().encode(self)


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
class ReadChunk:
    sequence: int
    monotonic_offset_ms: float
    data: bytes


@dataclass(frozen=True, slots=True)
class LineState:
    dtr: bool | None
    rts: bool | None


@dataclass(frozen=True, slots=True)
class SerialConfiguration:
    bytesize: int
    parity: str
    stopbits: float


@dataclass(frozen=True, slots=True)
class FrameCandidate:
    offset: int
    data: bytes
    valid: bool
    echo: bool
    error: str | None = None
    decoded: DecodedFrame | None = None


@dataclass(frozen=True, slots=True)
class StreamAnalysis:
    raw_response: bytes
    classification: TransportClassification
    leading_bytes: bytes
    echo_frames: tuple[bytes, ...]
    candidates: tuple[FrameCandidate, ...]
    valid_response_frames: tuple[DecodedFrame, ...]
    unparsed_bytes: bytes
    trailing_bytes: bytes
    partial_echo: bytes | None = None


@dataclass(frozen=True, slots=True)
class Exchange:
    request_payload: bytes
    request_frame: bytes
    chunks: tuple[ReadChunk, ...]
    raw_response: bytes
    analysis: StreamAnalysis
    line_state: LineState
    settle_delay: float
    total_timeout: float
    idle_timeout: float
    dtr_setting: LineSetting = LineSetting.AUTO
    rts_setting: LineSetting = LineSetting.AUTO
    operation: str = "probe"

    @property
    def logical_request(self) -> bytes:
        return self.request_payload

    @property
    def transmitted_frame(self) -> bytes:
        return self.request_frame

    @property
    def leading_bytes(self) -> bytes:
        return self.analysis.leading_bytes

    @property
    def received_frame(self) -> bytes:
        frames = self.analysis.valid_response_frames
        return frames[0].original if frames else b""

    @property
    def expected_frame_size(self) -> int | None:
        return None

    @property
    def complete(self) -> bool:
        return self.analysis.classification is not TransportClassification.INCOMPLETE_RESPONSE

    @property
    def response(self) -> bytes:
        return self.raw_response


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
    idle_timeout: float = 0.2
    settle_delay: float = 0.1
    transport_classification: TransportClassification = TransportClassification.NO_RESPONSE
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
    driver_id: str = "quansheng"
    driver_version: str = "1.0"


@dataclass(frozen=True, slots=True)
class Capture:
    schema_version: int
    created_utc: str
    qsidentify_version: str
    port: PortInfo
    baud_rate: int
    serial_configuration: SerialConfiguration
    operation: str
    total_timeout: float
    idle_timeout: float
    settle_delay: float
    dtr_setting: LineSetting
    rts_setting: LineSetting
    line_state: LineState
    transmit_performed: bool
    logical_request_payload_hex: str
    encoded_transmitted_frame_hex: str
    read_chunks: tuple[ReadChunk, ...]
    raw_response_hex: str
    leading_bytes_hex: str
    echo_frames_hex: tuple[str, ...]
    candidate_frames: tuple[FrameCandidate, ...]
    decoded_valid_frames_hex: tuple[str, ...]
    unparsed_bytes_hex: str
    trailing_bytes_hex: str
    stream_classification: TransportClassification
    report: ProbeReport
    safety: dict[str, str]
    driver_id: str = "quansheng"
    driver_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return capture_to_dict(self)

    @property
    def timeout(self) -> float:
        return self.total_timeout

    @property
    def leading_response_bytes_hex(self) -> str:
        return self.leading_bytes_hex

    @property
    def received_frame_hex(self) -> str:
        return self.decoded_valid_frames_hex[0] if self.decoded_valid_frames_hex else ""

    @property
    def decoded_payload_hex(self) -> str:
        for candidate in self.candidate_frames:
            if candidate.valid and not candidate.echo and candidate.decoded is not None:
                return candidate.decoded.payload.hex()
        return ""

    @property
    def checksum_status(self) -> ChecksumStatus | None:
        for candidate in self.candidate_frames:
            if candidate.valid and not candidate.echo and candidate.decoded is not None:
                return candidate.decoded.checksum_status
        return None


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
        "idle_timeout": report.idle_timeout,
        "settle_delay": report.settle_delay,
        "transport_classification": report.transport_classification.value,
        "warnings": list(report.warnings),
    }


def capture_to_dict(capture: Capture) -> dict[str, Any]:
    return {
        "baud_rate": capture.baud_rate,
        "candidate_frames": [
            {
                "data_hex": item.data.hex(),
                "echo": item.echo,
                "error": item.error,
                "offset": item.offset,
                "valid": item.valid,
            }
            for item in capture.candidate_frames
        ],
        "created_utc": capture.created_utc,
        "decoded_valid_frames_hex": list(capture.decoded_valid_frames_hex),
        "dtr_setting": capture.dtr_setting.value,
        "driver_id": capture.driver_id,
        "driver_version": capture.driver_version,
        "encoded_transmitted_frame_hex": capture.encoded_transmitted_frame_hex,
        "echo_frames_hex": list(capture.echo_frames_hex),
        "idle_timeout": capture.idle_timeout,
        "leading_bytes_hex": capture.leading_bytes_hex,
        "line_state": {"dtr": capture.line_state.dtr, "rts": capture.line_state.rts},
        "logical_request_payload_hex": capture.logical_request_payload_hex,
        "operation": capture.operation,
        "port": port_to_dict(capture.port),
        "probe_report": probe_report_to_dict(capture.report),
        "qsidentify_version": capture.qsidentify_version,
        "raw_response_hex": capture.raw_response_hex,
        "read_chunks": [
            {
                "data_hex": chunk.data.hex(),
                "monotonic_offset_ms": chunk.monotonic_offset_ms,
                "sequence": chunk.sequence,
            }
            for chunk in capture.read_chunks
        ],
        "rts_setting": capture.rts_setting.value,
        "serial_configuration": {
            "bytesize": capture.serial_configuration.bytesize,
            "parity": capture.serial_configuration.parity,
            "stopbits": capture.serial_configuration.stopbits,
        },
        "safety": dict(capture.safety),
        "schema_version": capture.schema_version,
        "settle_delay": capture.settle_delay,
        "stream_classification": capture.stream_classification.value,
        "total_timeout": capture.total_timeout,
        "trailing_bytes_hex": capture.trailing_bytes_hex,
        "transmit_performed": capture.transmit_performed,
        "unparsed_bytes_hex": capture.unparsed_bytes_hex,
    }
