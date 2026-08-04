from __future__ import annotations

import json
import os
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, TypeVar

from .models import (
    Capture,
    ChecksumStatus,
    Confidence,
    Evidence,
    MessageType,
    PortInfo,
    ProbeReport,
    ProbeResult,
)

CAPTURE_SCHEMA_VERSION = 1
T = TypeVar("T")


class CaptureError(ValueError):
    pass


def build_capture(result: ProbeResult, *, created_utc: str | None = None) -> Capture:
    frame = result.decoded.frame
    port = _capture_safe_port(result.report.port)
    report = replace(result.report, port=port)
    return Capture(
        schema_version=CAPTURE_SCHEMA_VERSION,
        created_utc=created_utc or datetime.now(UTC).replace(microsecond=0).isoformat(),
        qsidentify_version=result.report.qsidentify_version,
        port=port,
        baud_rate=result.report.baud_rate,
        timeout=result.report.timeout,
        logical_request_payload_hex=result.exchange.logical_request.hex(),
        encoded_transmitted_frame_hex=result.exchange.transmitted_frame.hex(),
        leading_response_bytes_hex=result.exchange.leading_bytes.hex(),
        received_frame_hex=result.exchange.received_frame.hex(),
        decoded_payload_hex=frame.payload.hex() if frame else "",
        checksum_status=frame.checksum_status if frame else None,
        report=report,
        safety={
            "classification": "read-only",
            "command": "identify-handshake",
            "arbitrary_transmit": "disabled",
        },
    )


def _capture_safe_port(port: PortInfo) -> PortInfo:
    home = str(Path.home())
    device = port.device
    if device == home or device.startswith(home + os.sep):
        device = "<redacted-home-path>"
    return replace(port, device=device)


def write_capture(path: Path, capture: Capture) -> None:
    payload = json.dumps(capture.to_dict(), indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def _fail(message: str) -> NoReturn:
    raise CaptureError(message)


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"Capture field '{field}' must be an object.")
    return value


def _required(raw: dict[str, Any], field: str, expected: type[T]) -> T:
    if field not in raw:
        _fail(f"Capture is missing required field '{field}'.")
    value = raw[field]
    if not isinstance(value, expected) or expected is int and isinstance(value, bool):
        _fail(f"Capture field '{field}' has the wrong type.")
    return value


def _number(raw: dict[str, Any], field: str) -> float:
    if field not in raw:
        _fail(f"Capture is missing required field '{field}'.")
    value = raw[field]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"Capture field '{field}' has the wrong type.")
    return float(value)


def _optional_string(raw: dict[str, Any], field: str) -> str | None:
    value = raw.get(field)
    if value is not None and not isinstance(value, str):
        _fail(f"Capture field '{field}' must be a string or null.")
    return value


def _hex(raw: dict[str, Any], field: str) -> str:
    value = _required(raw, field, str)
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise CaptureError(f"Capture field '{field}' is not valid hexadecimal.") from exc
    if len(value) % 2 or value.lower() != value or " " in value:
        _fail(f"Capture field '{field}' must use canonical lowercase hexadecimal.")
    return value


def _port(raw: dict[str, Any]) -> PortInfo:
    vid = raw.get("vid")
    pid = raw.get("pid")
    for field, value in (("vid", vid), ("pid", pid)):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF
        ):
            _fail(f"Capture port field '{field}' must be a USB identifier or null.")
    return PortInfo(
        device=_required(raw, "device", str),
        description=_optional_string(raw, "description"),
        manufacturer=_optional_string(raw, "manufacturer"),
        product=_optional_string(raw, "product"),
        serial_number=_optional_string(raw, "serial_number"),
        vid=vid,
        pid=pid,
    )


def _report(raw: dict[str, Any]) -> ProbeReport:
    try:
        confidence = Confidence(_required(raw, "confidence", str))
        message_type = MessageType(_required(raw, "message_type", str))
    except ValueError as exc:
        raise CaptureError(f"Invalid report enum value: {exc}") from exc
    evidence_raw = _required(raw, "evidence", list)
    warnings_raw = _required(raw, "warnings", list)
    evidence_items: list[Evidence] = []
    for item in evidence_raw:
        evidence_item = _mapping(item, "evidence item")
        evidence_items.append(
            Evidence(
                kind=_required(evidence_item, "kind", str),
                value=_required(evidence_item, "value", str),
                source=_required(evidence_item, "source", str),
            )
        )
    evidence = tuple(evidence_items)
    if not all(isinstance(item, str) for item in warnings_raw):
        _fail("Capture report warnings must be strings.")
    return ProbeReport(
        schema_version=_required(raw, "schema_version", int),
        qsidentify_version=_required(raw, "qsidentify_version", str),
        port=_port(_mapping(_required(raw, "port", dict), "probe_report.port")),
        baud_rate=_required(raw, "baud_rate", int),
        timeout=_number(raw, "timeout"),
        operating_mode=_required(raw, "operating_mode", str),
        response_received=_required(raw, "response_received", bool),
        frame_detected=_required(raw, "frame_detected", bool),
        frame_complete=_required(raw, "frame_complete", bool),
        message_type=message_type,
        reported_version=_optional_string(raw, "reported_version"),
        reported_bootloader_version=_optional_string(raw, "reported_bootloader_version"),
        detected_protocol=_optional_string(raw, "detected_protocol"),
        inferred_family=_optional_string(raw, "inferred_family"),
        confidence=confidence,
        evidence=evidence,
        warnings=tuple(warnings_raw),
    )


def read_capture(path: Path) -> Capture:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CaptureError(f"Could not read capture: {exc}") from exc
    raw = _mapping(parsed, "root")
    schema = _required(raw, "schema_version", int)
    if schema != CAPTURE_SCHEMA_VERSION:
        raise CaptureError(
            f"Unsupported capture schema version {schema}; expected {CAPTURE_SCHEMA_VERSION}."
        )
    if "checksum_status" not in raw:
        _fail("Capture is missing required field 'checksum_status'.")
    status_raw = raw["checksum_status"]
    if status_raw is not None and not isinstance(status_raw, str):
        _fail("Capture field 'checksum_status' must be a string or null.")
    try:
        status = ChecksumStatus(status_raw) if isinstance(status_raw, str) else None
    except ValueError as exc:
        raise CaptureError(f"Invalid checksum status: {status_raw}") from exc
    safety_raw = _mapping(_required(raw, "safety", dict), "safety")
    if not all(isinstance(value, str) for value in safety_raw.values()):
        _fail("Capture safety values must be strings.")
    report = _report(_mapping(_required(raw, "probe_report", dict), "probe_report"))
    created_utc = _required(raw, "created_utc", str)
    try:
        created = datetime.fromisoformat(created_utc)
    except ValueError as exc:
        raise CaptureError("Capture field 'created_utc' is not ISO-8601.") from exc
    if created.tzinfo is None or created.utcoffset() is None:
        _fail("Capture field 'created_utc' must include a UTC offset.")
    port = _port(_mapping(_required(raw, "port", dict), "port"))
    version = _required(raw, "qsidentify_version", str)
    baud_rate = _required(raw, "baud_rate", int)
    timeout = _number(raw, "timeout")
    if baud_rate <= 0 or timeout <= 0:
        _fail("Capture baud_rate and timeout must be positive.")
    if report.schema_version != schema:
        _fail("Capture and probe report schema versions do not match.")
    if report.qsidentify_version != version:
        _fail("Capture and probe report package versions do not match.")
    if report.port != port or report.baud_rate != baud_rate or report.timeout != timeout:
        _fail("Capture and probe report transport metadata do not match.")
    return Capture(
        schema_version=schema,
        created_utc=created_utc,
        qsidentify_version=version,
        port=port,
        baud_rate=baud_rate,
        timeout=timeout,
        logical_request_payload_hex=_hex(raw, "logical_request_payload_hex"),
        encoded_transmitted_frame_hex=_hex(raw, "encoded_transmitted_frame_hex"),
        leading_response_bytes_hex=_hex(raw, "leading_response_bytes_hex"),
        received_frame_hex=_hex(raw, "received_frame_hex"),
        decoded_payload_hex=_hex(raw, "decoded_payload_hex"),
        checksum_status=status,
        report=report,
        safety=dict(safety_raw),
    )
