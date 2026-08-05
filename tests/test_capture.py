import json
from dataclasses import replace
from pathlib import Path

import pytest

from qsidentify import __version__
from qsidentify.capture import CaptureError, build_capture, read_capture, write_capture
from qsidentify.models import (
    Confidence,
    DecodedResponse,
    Exchange,
    LineState,
    MessageType,
    PortInfo,
    ProbeReport,
    ProbeResult,
    ReadChunk,
)
from qsidentify.protocol.commands import IDENTIFY_HANDSHAKE
from qsidentify.protocol.decoder import decode_response
from qsidentify.protocol.frame import encode_frame
from qsidentify.protocol.stream import analyze_stream


def result_fixture(*, operation: str = "probe", response: bytes | None = None) -> ProbeResult:
    port = PortInfo("/dev/ttyUSB0", vid=0x1A86, pid=0x7523)
    request = IDENTIFY_HANDSHAKE.payload if operation == "probe" else b""
    transmitted = IDENTIFY_HANDSHAKE.encoded_frame() if operation == "probe" else b""
    response = response if response is not None else encode_frame(b"\x15\x05V1.0\x00")
    analysis = analyze_stream(response, transmitted)
    decoded = (
        decode_response(analysis.valid_response_frames[0].original)
        if analysis.valid_response_frames
        else DecodedResponse(
            None,
            None,
            None,
            MessageType.NO_RESPONSE,
            None,
            Confidence.NONE,
            (),
            (),
        )
    )
    exchange = Exchange(
        request,
        transmitted,
        (ReadChunk(1, 1.25, response),) if response else (),
        response,
        analysis,
        LineState(False, False),
        0.1 if operation == "probe" else 0.0,
        3.0,
        0.2,
        operation=operation,
    )
    report = ProbeReport(
        schema_version=2,
        qsidentify_version=__version__,
        port=port,
        baud_rate=38400,
        timeout=3.0,
        idle_timeout=0.2,
        settle_delay=exchange.settle_delay,
        transport_classification=analysis.classification,
        operating_mode="normal-programming-mode" if decoded.frame else "unknown",
        response_received=bool(response),
        frame_detected=bool(analysis.candidates),
        frame_complete=bool(analysis.valid_response_frames),
        message_type=decoded.message_type,
        reported_version=decoded.reported_version,
        detected_protocol=decoded.detected_protocol,
        confidence=decoded.confidence,
        evidence=decoded.evidence,
        warnings=decoded.warnings,
    )
    return ProbeResult(report, exchange, decoded)


def test_v3_roundtrip_is_deterministic_and_preserves_stream(tmp_path: Path) -> None:
    capture = build_capture(result_fixture(), created_utc="2026-08-04T12:00:00+00:00")
    first, second = tmp_path / "one.json", tmp_path / "two.json"
    write_capture(first, capture)
    write_capture(second, capture)
    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes().endswith(b"\n")
    assert read_capture(first) == capture
    assert capture.raw_response_hex == result_fixture().exchange.raw_response.hex()
    assert capture.transmit_performed
    assert capture.driver_id == "quansheng"
    assert capture.driver_version == "1.0"


def test_v2_capture_defaults_to_historical_quansheng_driver(tmp_path: Path) -> None:
    data = build_capture(result_fixture(), created_utc="2026-08-04T12:00:00+00:00").to_dict()
    data["schema_version"] = 2
    data.pop("driver_id")
    data.pop("driver_version")
    path = tmp_path / "v2.json"
    path.write_text(json.dumps(data))
    loaded = read_capture(path)
    assert loaded.schema_version == 2
    assert loaded.driver_id == "quansheng"


def test_monitor_capture_declares_no_transmit(tmp_path: Path) -> None:
    capture = build_capture(
        result_fixture(operation="monitor", response=b"spontaneous"),
        created_utc="2026-08-04T12:00:00+00:00",
    )
    path = tmp_path / "monitor.json"
    write_capture(path, capture)
    loaded = read_capture(path)
    assert loaded.operation == "monitor"
    assert not loaded.transmit_performed
    assert loaded.encoded_transmitted_frame_hex == ""


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update(schema_version=99),
        lambda data: data["read_chunks"][0].pop("data_hex"),
        lambda data: data.update(raw_response_hex="zz"),
        lambda data: data.update(operation="monitor"),
        lambda data: data.update(transmit_performed=False),
        lambda data: data["safety"].update(command="not-allowlisted"),
        lambda data: data.update(logical_request_payload_hex="00"),
        lambda data: data.update(encoded_transmitted_frame_hex="abcd"),
        lambda data: data.update(driver_id="missing"),
        lambda data: data["safety"].update(classification="unsafe"),
        lambda data: data["probe_report"].update(transport_classification="null-byte-response"),
        lambda data: data["read_chunks"][0].update(monotonic_offset_ms=-1),
        lambda data: data["read_chunks"][0].update(data_hex=""),
    ],
)
def test_v2_schema_validation(tmp_path: Path, mutation) -> None:  # type: ignore[no-untyped-def]
    data = build_capture(result_fixture(), created_utc="2026-08-04T12:00:00+00:00").to_dict()
    mutation(data)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    with pytest.raises(CaptureError):
        read_capture(path)


def test_v1_capture_is_readable(tmp_path: Path) -> None:
    response = encode_frame(b"\x15\x05V1.0\x00")
    report = replace(result_fixture().report, schema_version=1).to_dict()
    data = {
        "schema_version": 1,
        "created_utc": "2026-08-04T12:00:00+00:00",
        "qsidentify_version": "0.1.1",
        "port": report["port"],
        "baud_rate": 38400,
        "timeout": 1.0,
        "logical_request_payload_hex": IDENTIFY_HANDSHAKE.payload.hex(),
        "encoded_transmitted_frame_hex": IDENTIFY_HANDSHAKE.encoded_frame().hex(),
        "leading_response_bytes_hex": "99",
        "received_frame_hex": response.hex(),
        "decoded_payload_hex": "",
        "checksum_status": "valid",
        "probe_report": {**report, "qsidentify_version": "0.1.1", "timeout": 1.0},
        "safety": {"classification": "read-only", "command": "identify-handshake"},
    }
    path = tmp_path / "v1.json"
    path.write_text(json.dumps(data))
    loaded = read_capture(path)
    assert loaded.schema_version == 1
    assert loaded.raw_response_hex == "99" + response.hex()


def test_capture_redacts_home_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/local-user")))
    result = result_fixture()
    private = PortInfo("/home/local-user/virtual-radio")
    capture = build_capture(
        ProbeResult(replace(result.report, port=private), result.exchange, result.decoded)
    )
    assert capture.port.device == "<redacted-home-path>"
