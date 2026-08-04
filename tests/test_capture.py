from pathlib import Path

from qsidentify.capture import build_capture, read_capture, write_capture
from qsidentify.models import Confidence, Exchange, PortInfo, ProbeReport, ProbeResult


def test_capture_roundtrip(tmp_path: Path) -> None:
    port = PortInfo(device="/dev/ttyUSB0", vid=0x1A86, pid=0x7523)
    report = ProbeReport(
        schema_version=1,
        qsidentify_version="0.1.0",
        port=port,
        baud_rate=38400,
        operating_mode="normal-programming-mode",
        response_received=True,
        reported_version="k5_2.01.27",
        detected_protocol="test",
        inferred_family="test-family",
        confidence=Confidence.MEDIUM,
    )
    result = ProbeResult(
        report=report,
        exchange=Exchange(request=b"request", response=b"response"),
    )

    path = tmp_path / "capture.json"
    write_capture(path, build_capture(result))
    loaded = read_capture(path)

    assert loaded.port == port
    assert loaded.request_hex == b"request".hex()
    assert loaded.response_hex == b"response".hex()
    assert loaded.report.reported_version == "k5_2.01.27"
