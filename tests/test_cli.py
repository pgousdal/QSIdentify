import json
from pathlib import Path

from typer.testing import CliRunner

from qsidentify import __version__
from qsidentify.cli import app
from qsidentify.models import (
    Confidence,
    DecodedResponse,
    Exchange,
    MessageType,
    PortInfo,
    ProbeReport,
    ProbeResult,
)


def probe_result(message_type: MessageType) -> ProbeResult:
    port = PortInfo("test-port")
    decoded = DecodedResponse(
        reported_version="V1.0" if message_type is MessageType.FIRMWARE_IDENTIFICATION else None,
        reported_bootloader_version=None,
        detected_protocol="Quansheng framed identification response",
        message_type=message_type,
        inferred_family=None,
        confidence=Confidence.LOW,
        evidence=(),
        warnings=(),
    )
    report = ProbeReport(
        schema_version=1,
        qsidentify_version=__version__,
        port=port,
        baud_rate=38400,
        timeout=1.0,
        operating_mode="unknown",
        response_received=message_type is not MessageType.NO_RESPONSE,
        frame_detected=False,
        frame_complete=False,
        message_type=message_type,
        reported_version=decoded.reported_version,
        detected_protocol=decoded.detected_protocol,
        confidence=decoded.confidence,
    )
    return ProbeResult(report, Exchange(b"request", b"frame", b"", b""), decoded)


def test_probe_json_stdout_contains_json_only(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    result = probe_result(MessageType.FIRMWARE_IDENTIFICATION)
    monkeypatch.setattr("qsidentify.cli.find_port", lambda _device: result.report.port)
    monkeypatch.setattr("qsidentify.cli.probe_port", lambda *_args, **_kwargs: result)
    invocation = CliRunner().invoke(app, ["probe", "test-port", "--json"])
    assert invocation.exit_code == 0
    assert json.loads(invocation.stdout)["reported_version"] == "V1.0"
    assert "QSIdentify" not in invocation.stdout


def test_no_response_has_stable_warning_exit(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    result = probe_result(MessageType.NO_RESPONSE)
    monkeypatch.setattr("qsidentify.cli.find_port", lambda _device: result.report.port)
    monkeypatch.setattr("qsidentify.cli.probe_port", lambda *_args, **_kwargs: result)
    invocation = CliRunner().invoke(app, ["probe", "test-port", "--json"])
    assert invocation.exit_code == 1
    assert json.loads(invocation.stdout)["message_type"] == "no-response"


def test_invalid_capture_has_stable_input_exit(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{")
    invocation = CliRunner().invoke(app, ["decode", str(path)])
    assert invocation.exit_code == 3
    assert "Invalid capture:" in invocation.output
    assert "Traceback" not in invocation.output
