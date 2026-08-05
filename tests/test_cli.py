import json
from pathlib import Path

from typer.testing import CliRunner

from qsidentify import __version__
from qsidentify.capture import build_capture, write_capture
from qsidentify.cli import app
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
from qsidentify.protocol.stream import analyze_stream


def result(operation: str = "probe") -> ProbeResult:
    raw = b"" if operation == "probe" else b"spontaneous"
    analysis = analyze_stream(raw)
    port = PortInfo("test-port")
    decoded = DecodedResponse(
        None, None, None, MessageType.NO_RESPONSE, None, Confidence.NONE, (), ()
    )
    report = ProbeReport(
        2,
        __version__,
        port,
        38400,
        3.0,
        "unknown",
        bool(raw),
        False,
        False,
        MessageType.NO_RESPONSE,
        settle_delay=0.0,
        transport_classification=analysis.classification,
    )
    exchange = Exchange(
        b"request" if operation == "probe" else b"",
        b"frame" if operation == "probe" else b"",
        (ReadChunk(1, 1.0, raw),) if raw else (),
        raw,
        analysis,
        LineState(None, None),
        0.0,
        3.0,
        0.2,
        operation=operation,
    )
    return ProbeResult(report, exchange, decoded)


def test_probe_json_stdout_contains_json_only(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    value = result()
    monkeypatch.setattr("qsidentify.cli.find_port", lambda _device: value.report.port)
    monkeypatch.setattr("qsidentify.cli.probe_port", lambda *_args, **_kwargs: value)
    invocation = CliRunner().invoke(app, ["probe", "test-port", "--json"])
    assert invocation.exit_code == 1
    assert json.loads(invocation.stdout)["qsidentify_version"] == "1.1.0"
    assert "QSIdentify" not in invocation.stdout


def test_probe_json_can_include_offline_firmware_advice(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    value = result()
    monkeypatch.setattr("qsidentify.cli.find_port", lambda _device: value.report.port)
    monkeypatch.setattr("qsidentify.cli.probe_port", lambda *_args, **_kwargs: value)
    invocation = CliRunner().invoke(
        app,
        ["probe", "test-port", "--json", "--firmware-advice", "--model", "UV-K5(8)"],
    )
    assert invocation.exit_code == 1
    parsed = json.loads(invocation.stdout)
    assert parsed["firmware_advisory"]["marketed_model"] == "UV-K5(8)"


def test_version_uses_canonical_package_version() -> None:
    invocation = CliRunner().invoke(app, ["--version"])
    assert invocation.exit_code == 0
    assert invocation.stdout == f"QSIdentify {__version__}\n"


def test_monitor_json_stdout_contains_json_only(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    value = result("monitor")
    monkeypatch.setattr("qsidentify.cli.find_port", lambda _device: value.report.port)
    monkeypatch.setattr("qsidentify.cli.monitor_port", lambda *_args, **_kwargs: value)
    invocation = CliRunner().invoke(app, ["monitor", "test-port", "--json"])
    assert invocation.exit_code == 1
    assert json.loads(invocation.stdout)["transport_classification"] == "unframed-binary-response"
    assert "QSIdentify" not in invocation.stdout


def test_invalid_capture_has_stable_input_exit(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{")
    invocation = CliRunner().invoke(app, ["decode", str(path)])
    assert invocation.exit_code == 3
    assert "Invalid capture:" in invocation.output
    assert "Traceback" not in invocation.output


def test_invalid_line_setting_and_timing_are_controlled() -> None:
    runner = CliRunner()
    assert runner.invoke(app, ["probe", "test", "--dtr", "maybe"]).exit_code == 2
    assert runner.invoke(app, ["monitor", "test", "--duration", "0"]).exit_code == 2


def test_compare_output(tmp_path: Path) -> None:
    paths = [tmp_path / "one.json", tmp_path / "two.json"]
    for path in paths:
        write_capture(path, build_capture(result("monitor")))
    invocation = CliRunner().invoke(app, ["compare", *(str(path) for path in paths)])
    assert invocation.exit_code == 0
    assert "Exact match:" in invocation.stdout
    assert "SHA-256" in invocation.stdout


def test_offline_catalog_commands() -> None:
    runner = CliRunner()
    validation = runner.invoke(app, ["firmware-catalog-validate"])
    firmware = runner.invoke(app, ["firmware-list"])
    hardware = runner.invoke(app, ["hardware-list"])
    assert validation.exit_code == 0
    assert "2026.08 is valid" in validation.stdout
    assert firmware.exit_code == 0 and "egzumer-legacy" in firmware.stdout
    assert hardware.exit_code == 0 and "DP32G030" in hardware.stdout


def test_driver_commands_are_stable_and_offline() -> None:
    runner = CliRunner()
    listing = runner.invoke(app, ["drivers"])
    detail = runner.invoke(app, ["driver-info", "quansheng"])
    missing = runner.invoke(app, ["driver-info", "missing"])
    assert listing.exit_code == 0 and "quansheng" in listing.stdout
    assert detail.exit_code == 0
    assert "Quansheng framed protocol" in detail.stdout
    assert "identify-handshake" in detail.stdout
    assert missing.exit_code == 3 and "Unknown driver" in missing.output


def test_firmware_advice_json_is_json_only(tmp_path: Path) -> None:
    path = tmp_path / "capture.json"
    write_capture(path, build_capture(result("monitor")))
    invocation = CliRunner().invoke(
        app, ["firmware-advice", str(path), "--model", "UV-K5(8)", "--json"]
    )
    assert invocation.exit_code == 0
    parsed = json.loads(invocation.stdout)
    assert parsed["firmware_advisory"]["marketed_model"] == "UV-K5(8)"


def test_firmware_advice_conflict_has_controlled_exit(tmp_path: Path) -> None:
    path = tmp_path / "capture.json"
    write_capture(path, build_capture(result("monitor")))
    invocation = CliRunner().invoke(
        app,
        [
            "firmware-advice",
            str(path),
            "--hardware-revision",
            "V3",
            "--mcu",
            "DP32G030",
        ],
    )
    assert invocation.exit_code == 2
    assert "conflicting-evidence" in invocation.stdout
    assert "Traceback" not in invocation.output
