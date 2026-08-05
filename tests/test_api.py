from types import SimpleNamespace

from qsidentify import IdentificationResult, identify
from qsidentify.models import MessageType, PortInfo, ProbeReport


def test_public_identify_api_hides_transport(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    report = ProbeReport(
        schema_version=2,
        qsidentify_version="1.0.0",
        port=PortInfo("test-port"),
        baud_rate=38400,
        timeout=3.0,
        operating_mode="unknown",
        response_received=False,
        frame_detected=False,
        frame_complete=False,
        message_type=MessageType.NO_RESPONSE,
    )
    monkeypatch.setattr("qsidentify.api.find_port", lambda device: PortInfo(device))
    monkeypatch.setattr(
        "qsidentify.api.probe_port",
        lambda *_args, **_kwargs: SimpleNamespace(report=report),
    )
    result = identify("test-port")
    assert isinstance(result, IdentificationResult)
    assert result.driver.id == "quansheng"
    assert result.report is report
    assert not hasattr(result, "exchange")
    assert result.to_dict()["driver_version"] == "1.0"
