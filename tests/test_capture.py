import json
from dataclasses import replace
from pathlib import Path

import pytest

from qsidentify import __version__
from qsidentify.capture import CaptureError, build_capture, read_capture, write_capture
from qsidentify.models import Exchange, MessageType, PortInfo, ProbeReport, ProbeResult
from qsidentify.protocol.decoder import decode_response
from qsidentify.protocol.frame import encode_frame


def result_fixture() -> ProbeResult:
    port = PortInfo(device="/dev/ttyUSB0", vid=0x1A86, pid=0x7523)
    logical = bytes.fromhex("14 05 04 00 6a 39 57 64")
    response = encode_frame(b"\x15\x05V1.0\x00")
    decoded = decode_response(response)
    report = ProbeReport(
        schema_version=1,
        qsidentify_version=__version__,
        port=port,
        baud_rate=38400,
        timeout=1.0,
        operating_mode="normal-programming-mode",
        response_received=True,
        frame_detected=True,
        frame_complete=True,
        message_type=MessageType.FIRMWARE_IDENTIFICATION,
        reported_version="V1.0",
        detected_protocol=decoded.detected_protocol,
        confidence=decoded.confidence,
        evidence=decoded.evidence,
        warnings=decoded.warnings,
    )
    return ProbeResult(
        report=report,
        exchange=Exchange(logical, encode_frame(logical), b"\x99", response),
        decoded=decoded,
    )


def test_capture_roundtrip_is_deterministic_and_preserves_bytes(tmp_path: Path) -> None:
    capture = build_capture(result_fixture(), created_utc="2026-08-04T12:00:00+00:00")
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_capture(first, capture)
    write_capture(second, capture)
    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes().endswith(b"\n")
    assert not list(tmp_path.glob("*.tmp"))
    loaded = read_capture(first)
    assert loaded == capture
    assert loaded.leading_response_bytes_hex == "99"
    assert loaded.received_frame_hex == result_fixture().exchange.received_frame.hex()


def test_capture_json_keys_are_sorted(tmp_path: Path) -> None:
    path = tmp_path / "capture.json"
    write_capture(path, build_capture(result_fixture(), created_utc="2026-08-04T12:00:00+00:00"))
    assert list(json.loads(path.read_text()).keys()) == sorted(json.loads(path.read_text()).keys())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update(schema_version=2),
        lambda data: data.pop("received_frame_hex"),
        lambda data: data.update(received_frame_hex="zz"),
        lambda data: data.pop("checksum_status"),
        lambda data: data.update(created_utc="not-a-date"),
        lambda data: data["probe_report"].update(qsidentify_version="9.9.9"),
        lambda data: data["port"].update(vid=True),
    ],
)
def test_capture_schema_validation(tmp_path: Path, mutation: object) -> None:
    data = build_capture(result_fixture(), created_utc="2026-08-04T12:00:00+00:00").to_dict()
    mutation(data)  # type: ignore[operator]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    with pytest.raises(CaptureError):
        read_capture(path)


def test_malformed_json_is_controlled(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{")
    with pytest.raises(CaptureError, match="Could not read capture"):
        read_capture(path)


def test_capture_redacts_device_paths_under_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/local-user")))
    result = result_fixture()
    private_port = PortInfo(device="/home/local-user/virtual-radio")
    private_report = replace(result.report, port=private_port)
    private_result = ProbeResult(private_report, result.exchange, result.decoded)
    capture = build_capture(private_result, created_utc="2026-08-04T12:00:00+00:00")
    assert capture.port.device == "<redacted-home-path>"
    assert capture.report.port.device == "<redacted-home-path>"
