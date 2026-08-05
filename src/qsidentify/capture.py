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
    Confidence,
    Evidence,
    FrameCandidate,
    LineSetting,
    LineState,
    MessageType,
    PortInfo,
    ProbeReport,
    ProbeResult,
    ReadChunk,
    SerialConfiguration,
    TransportClassification,
)
from .protocol.commands import ALLOWLIST
from .protocol.stream import analyze_stream

CAPTURE_SCHEMA_VERSION = 2
SUPPORTED_CAPTURE_SCHEMAS = (1, 2)
T = TypeVar("T")


class CaptureError(ValueError):
    pass


def _capture_safe_port(port: PortInfo) -> PortInfo:
    home = str(Path.home())
    device = port.device
    if device == home or device.startswith(home + os.sep):
        device = "<redacted-home-path>"
    return replace(port, device=device)


def build_capture(result: ProbeResult, *, created_utc: str | None = None) -> Capture:
    exchange = result.exchange
    analysis = exchange.analysis
    port = _capture_safe_port(result.report.port)
    report = replace(result.report, port=port)
    transmit = exchange.operation == "probe"
    return Capture(
        schema_version=CAPTURE_SCHEMA_VERSION,
        created_utc=created_utc or datetime.now(UTC).replace(microsecond=0).isoformat(),
        qsidentify_version=result.report.qsidentify_version,
        operation=exchange.operation,
        port=port,
        baud_rate=result.report.baud_rate,
        serial_configuration=SerialConfiguration(8, "none", 1.0),
        total_timeout=exchange.total_timeout,
        idle_timeout=exchange.idle_timeout,
        settle_delay=exchange.settle_delay,
        dtr_setting=exchange.dtr_setting,
        rts_setting=exchange.rts_setting,
        line_state=exchange.line_state,
        transmit_performed=transmit,
        logical_request_payload_hex=exchange.request_payload.hex(),
        encoded_transmitted_frame_hex=exchange.request_frame.hex(),
        read_chunks=exchange.chunks,
        raw_response_hex=exchange.raw_response.hex(),
        leading_bytes_hex=analysis.leading_bytes.hex(),
        echo_frames_hex=tuple(frame.hex() for frame in analysis.echo_frames),
        candidate_frames=analysis.candidates,
        decoded_valid_frames_hex=tuple(
            frame.original.hex() for frame in analysis.valid_response_frames
        ),
        unparsed_bytes_hex=analysis.unparsed_bytes.hex(),
        trailing_bytes_hex=analysis.trailing_bytes.hex(),
        stream_classification=analysis.classification,
        report=report,
        safety={
            "classification": "read-only" if transmit else "passive-monitor",
            "command": "identify-handshake" if transmit else "",
            "arbitrary_transmit": "disabled",
        },
    )


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
    value: object = raw[field]
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
    vid, pid = raw.get("vid"), raw.get("pid")
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
        transport = TransportClassification(raw.get("transport_classification", "no-response"))
    except ValueError as exc:
        raise CaptureError(f"Invalid report enum value: {exc}") from exc
    evidence_raw = _required(raw, "evidence", list)
    warnings_raw = _required(raw, "warnings", list)
    evidence: list[Evidence] = []
    for item in evidence_raw:
        value = _mapping(item, "evidence item")
        evidence.append(
            Evidence(
                _required(value, "kind", str),
                _required(value, "value", str),
                _required(value, "source", str),
            )
        )
    if not all(isinstance(item, str) for item in warnings_raw):
        _fail("Capture report warnings must be strings.")
    return ProbeReport(
        schema_version=_required(raw, "schema_version", int),
        qsidentify_version=_required(raw, "qsidentify_version", str),
        port=_port(_mapping(_required(raw, "port", dict), "probe_report.port")),
        baud_rate=_required(raw, "baud_rate", int),
        timeout=_number(raw, "timeout"),
        idle_timeout=float(raw.get("idle_timeout", 0.2)),
        settle_delay=float(raw.get("settle_delay", 0.1)),
        transport_classification=transport,
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
        evidence=tuple(evidence),
        warnings=tuple(warnings_raw),
    )


def _created(raw: dict[str, Any]) -> str:
    value = _required(raw, "created_utc", str)
    try:
        created = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CaptureError("Capture field 'created_utc' is not ISO-8601.") from exc
    if created.tzinfo is None or created.utcoffset() is None:
        _fail("Capture field 'created_utc' must include a UTC offset.")
    return value


def _read_v1(raw: dict[str, Any]) -> Capture:
    report = _report(_mapping(_required(raw, "probe_report", dict), "probe_report"))
    leading = _hex(raw, "leading_response_bytes_hex")
    framed = _hex(raw, "received_frame_hex")
    transmitted = _hex(raw, "encoded_transmitted_frame_hex")
    response = bytes.fromhex(leading + framed)
    analysis = analyze_stream(response, bytes.fromhex(transmitted))
    chunks = (ReadChunk(1, 0.0, response),) if response else ()
    return Capture(
        schema_version=1,
        created_utc=_created(raw),
        qsidentify_version=_required(raw, "qsidentify_version", str),
        operation="probe",
        port=_port(_mapping(_required(raw, "port", dict), "port")),
        baud_rate=_required(raw, "baud_rate", int),
        serial_configuration=SerialConfiguration(8, "none", 1.0),
        total_timeout=_number(raw, "timeout"),
        idle_timeout=0.2,
        settle_delay=0.1,
        dtr_setting=LineSetting.AUTO,
        rts_setting=LineSetting.AUTO,
        line_state=LineState(None, None),
        transmit_performed=True,
        logical_request_payload_hex=_hex(raw, "logical_request_payload_hex"),
        encoded_transmitted_frame_hex=transmitted,
        read_chunks=chunks,
        raw_response_hex=response.hex(),
        leading_bytes_hex=analysis.leading_bytes.hex(),
        echo_frames_hex=tuple(item.hex() for item in analysis.echo_frames),
        candidate_frames=analysis.candidates,
        decoded_valid_frames_hex=tuple(
            item.original.hex() for item in analysis.valid_response_frames
        ),
        unparsed_bytes_hex=analysis.unparsed_bytes.hex(),
        trailing_bytes_hex=analysis.trailing_bytes.hex(),
        stream_classification=analysis.classification,
        report=report,
        safety=dict(_mapping(_required(raw, "safety", dict), "safety")),
    )


def _candidate(raw: dict[str, Any]) -> FrameCandidate:
    return FrameCandidate(
        offset=_required(raw, "offset", int),
        data=bytes.fromhex(_hex(raw, "data_hex")),
        valid=_required(raw, "valid", bool),
        echo=_required(raw, "echo", bool),
        error=_optional_string(raw, "error"),
    )


def _read_v2(raw: dict[str, Any]) -> Capture:
    operation = _required(raw, "operation", str)
    transmit = _required(raw, "transmit_performed", bool)
    if operation not in {"probe", "monitor"}:
        _fail("Capture operation must be probe or monitor.")
    if (operation == "monitor" and transmit) or (operation == "probe" and not transmit):
        _fail("Capture operation and transmit_performed are inconsistent.")
    safety = _mapping(_required(raw, "safety", dict), "safety")
    if not all(isinstance(value, str) for value in safety.values()):
        _fail("Capture safety values must be strings.")
    command = safety.get("command")
    allowed_commands = {item.name: item for item in ALLOWLIST}
    allowed = allowed_commands.get(command) if isinstance(command, str) else None
    if operation == "probe" and allowed is None:
        _fail("Probe capture must name an allowlisted command.")
    request = _hex(raw, "logical_request_payload_hex")
    transmitted = _hex(raw, "encoded_transmitted_frame_hex")
    if operation == "monitor" and (request or transmitted):
        _fail("Monitor capture cannot contain transmit bytes.")
    if operation == "probe":
        assert allowed is not None
        if request != allowed.payload.hex() or transmitted != allowed.encoded_frame().hex():
            _fail("Probe capture transmit bytes do not match its allowlisted command.")
        if safety.get("classification") != allowed.safety.value:
            _fail("Probe capture safety classification does not match its command.")
    chunks_raw = _required(raw, "read_chunks", list)
    chunks: list[ReadChunk] = []
    for item in chunks_raw:
        value = _mapping(item, "read chunk")
        chunks.append(
            ReadChunk(
                _required(value, "sequence", int),
                _number(value, "monotonic_offset_ms"),
                bytes.fromhex(_hex(value, "data_hex")),
            )
        )
    if any(not item.data for item in chunks):
        _fail("Read chunks must contain at least one byte.")
    if [item.sequence for item in chunks] != list(range(1, len(chunks) + 1)):
        _fail("Read chunk sequence numbers must be contiguous from one.")
    offsets = [item.monotonic_offset_ms for item in chunks]
    if any(value < 0 for value in offsets) or offsets != sorted(offsets):
        _fail("Read chunk monotonic offsets must be non-negative and ordered.")
    raw_response = _hex(raw, "raw_response_hex")
    if b"".join(item.data for item in chunks).hex() != raw_response:
        _fail("Read chunks do not reconstruct the combined raw response.")
    stored_candidates = tuple(
        _candidate(_mapping(item, "candidate frame"))
        for item in _required(raw, "candidate_frames", list)
    )
    try:
        stream_classification = TransportClassification(
            _required(raw, "stream_classification", str)
        )
        dtr_setting = LineSetting(_required(raw, "dtr_setting", str))
        rts_setting = LineSetting(_required(raw, "rts_setting", str))
    except ValueError as exc:
        raise CaptureError(f"Invalid capture enum value: {exc}") from exc
    analysis = analyze_stream(bytes.fromhex(raw_response), bytes.fromhex(transmitted))
    candidate_shape = tuple(
        (item.offset, item.data, item.valid, item.echo, item.error) for item in analysis.candidates
    )
    stored_shape = tuple(
        (item.offset, item.data, item.valid, item.echo, item.error) for item in stored_candidates
    )
    if candidate_shape != stored_shape or stream_classification is not analysis.classification:
        _fail("Stored stream analysis does not match the raw response.")
    derived_hex = {
        "leading_bytes_hex": analysis.leading_bytes.hex(),
        "unparsed_bytes_hex": analysis.unparsed_bytes.hex(),
        "trailing_bytes_hex": analysis.trailing_bytes.hex(),
    }
    for field, expected in derived_hex.items():
        if _hex(raw, field) != expected:
            _fail(f"Capture field '{field}' does not match the raw response.")
    stored_echoes = tuple(
        _hex({"item": item}, "item") for item in _required(raw, "echo_frames_hex", list)
    )
    if stored_echoes != tuple(item.hex() for item in analysis.echo_frames):
        _fail("Stored echo frames do not match the raw response.")
    stored_valid = tuple(
        _hex({"item": item}, "item") for item in _required(raw, "decoded_valid_frames_hex", list)
    )
    if stored_valid != tuple(item.original.hex() for item in analysis.valid_response_frames):
        _fail("Stored valid frames do not match the raw response.")
    line = _mapping(_required(raw, "line_state", dict), "line_state")
    for field in ("dtr", "rts"):
        if line.get(field) is not None and not isinstance(line.get(field), bool):
            _fail(f"Line state '{field}' must be boolean or null.")
    report = _report(_mapping(_required(raw, "probe_report", dict), "probe_report"))
    serial_raw = _mapping(_required(raw, "serial_configuration", dict), "serial_configuration")
    serial_configuration = SerialConfiguration(
        bytesize=_required(serial_raw, "bytesize", int),
        parity=_required(serial_raw, "parity", str),
        stopbits=_number(serial_raw, "stopbits"),
    )
    if serial_configuration != SerialConfiguration(8, "none", 1.0):
        _fail("Capture serial configuration is unsupported.")
    port = _port(_mapping(_required(raw, "port", dict), "port"))
    version = _required(raw, "qsidentify_version", str)
    baud = _required(raw, "baud_rate", int)
    total = _number(raw, "total_timeout")
    idle = _number(raw, "idle_timeout")
    settle = _number(raw, "settle_delay")
    if baud <= 0 or total <= 0 or idle <= 0 or idle > total or settle < 0:
        _fail("Capture serial timing values are invalid.")
    if report.port != port or report.qsidentify_version != version or report.baud_rate != baud:
        _fail("Capture and probe report metadata do not match.")
    if report.schema_version != 2 or report.timeout != total:
        _fail("Capture and probe report schema or timeout do not match.")
    if report.idle_timeout != idle or report.settle_delay != settle:
        _fail("Capture and probe report timing metadata do not match.")
    if report.transport_classification is not stream_classification:
        _fail("Capture and probe report transport classifications do not match.")
    if report.response_received != bool(raw_response):
        _fail("Probe report response state does not match the raw response.")
    if report.frame_complete != bool(analysis.valid_response_frames):
        _fail("Probe report frame state does not match the stream analysis.")
    return Capture(
        schema_version=2,
        created_utc=_created(raw),
        qsidentify_version=version,
        operation=operation,
        port=port,
        baud_rate=baud,
        serial_configuration=serial_configuration,
        total_timeout=total,
        idle_timeout=idle,
        settle_delay=settle,
        dtr_setting=dtr_setting,
        rts_setting=rts_setting,
        line_state=LineState(line.get("dtr"), line.get("rts")),
        transmit_performed=transmit,
        logical_request_payload_hex=request,
        encoded_transmitted_frame_hex=transmitted,
        read_chunks=tuple(chunks),
        raw_response_hex=raw_response,
        leading_bytes_hex=_hex(raw, "leading_bytes_hex"),
        echo_frames_hex=stored_echoes,
        candidate_frames=analysis.candidates,
        decoded_valid_frames_hex=stored_valid,
        unparsed_bytes_hex=_hex(raw, "unparsed_bytes_hex"),
        trailing_bytes_hex=_hex(raw, "trailing_bytes_hex"),
        stream_classification=stream_classification,
        report=report,
        safety={str(key): str(value) for key, value in safety.items()},
    )


def read_capture(path: Path) -> Capture:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CaptureError(f"Could not read capture: {exc}") from exc
    raw = _mapping(parsed, "root")
    schema = _required(raw, "schema_version", int)
    if schema not in SUPPORTED_CAPTURE_SCHEMAS:
        raise CaptureError(f"Unsupported capture schema version {schema}; supported: 1 and 2.")
    return _read_v1(raw) if schema == 1 else _read_v2(raw)
