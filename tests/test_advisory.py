from dataclasses import replace

import pytest

from qsidentify import __version__
from qsidentify.advisory import Compatibility, HardwareInput, ScopeConfidence, build_advisory
from qsidentify.capture import build_capture
from qsidentify.models import Exchange, LineState, PortInfo, ProbeReport, ProbeResult, ReadChunk
from qsidentify.protocol.commands import IDENTIFY_HANDSHAKE
from qsidentify.protocol.decoder import decode_response
from qsidentify.protocol.frame import encode_frame
from qsidentify.protocol.stream import analyze_stream


def capture_with_version(version: str | None = "2.01.36"):  # type: ignore[no-untyped-def]
    payload = (
        b"\x15\x05unknown\x00" if version is None else b"\x15\x05" + version.encode() + b"\x00"
    )
    response = encode_frame(payload)
    analysis = analyze_stream(response, IDENTIFY_HANDSHAKE.encoded_frame())
    decoded = decode_response(response)
    port = PortInfo("test-port")
    report = ProbeReport(
        schema_version=2,
        qsidentify_version=__version__,
        port=port,
        baud_rate=38400,
        timeout=3.0,
        operating_mode="normal-programming-mode",
        response_received=True,
        frame_detected=True,
        frame_complete=True,
        message_type=decoded.message_type,
        transport_classification=analysis.classification,
        reported_version=decoded.reported_version,
        detected_protocol=decoded.detected_protocol,
        confidence=decoded.confidence,
        evidence=decoded.evidence,
        warnings=decoded.warnings,
    )
    exchange = Exchange(
        IDENTIFY_HANDSHAKE.payload,
        IDENTIFY_HANDSHAKE.encoded_frame(),
        (ReadChunk(1, 1.0, response),),
        response,
        analysis,
        LineState(False, False),
        0.1,
        3.0,
        0.2,
    )
    return build_capture(
        ProbeResult(report, exchange, decoded), created_utc="2026-08-05T00:00:00+00:00"
    )


def compatibility(advisory, catalog_id: str) -> Compatibility:  # type: ignore[no-untyped-def]
    return next(item.compatibility for item in advisory.entries if item.catalog_id == catalog_id)


def test_firmware_string_without_hardware_stays_unknown() -> None:
    advisory = build_advisory(capture_with_version())
    assert advisory.observed_firmware == "2.01.36"
    assert advisory.hardware_revision is None and advisory.mcu is None
    assert all(item.compatibility is Compatibility.UNKNOWN for item in advisory.entries)
    assert advisory.confidence.firmware_version is ScopeConfidence.CONFIRMED
    assert advisory.confidence.mcu_family is ScopeConfidence.UNKNOWN


def test_marketed_model_alone_does_not_identify_revision() -> None:
    advisory = build_advisory(capture_with_version(), HardwareInput(model="UV-K5(8)"))
    assert advisory.marketed_model == "UV-K5(8)"
    assert advisory.hardware_revision is None
    assert all(item.compatibility is Compatibility.UNKNOWN for item in advisory.entries)


@pytest.mark.parametrize(
    ("hardware_input", "revision", "mcu", "supported", "rejected"),
    [
        (
            HardwareInput(hardware_revision="V1"),
            "Legacy/V1",
            "DP32G030",
            "egzumer-legacy",
            "f4hwn-fusion-v3",
        ),
        (HardwareInput(mcu="DP32G030"), None, "DP32G030", "f4hwn-legacy", "f4hwn-fusion-v3"),
        (
            HardwareInput(hardware_revision="V1", mcu="DP32G030"),
            "Legacy/V1",
            "DP32G030",
            "egzumer-legacy",
            "f4hwn-fusion-v3",
        ),
        (
            HardwareInput(hardware_revision="V3", mcu="PY32F071"),
            "V3",
            "PY32F071",
            "f4hwn-fusion-v3",
            "egzumer-legacy",
        ),
    ],
)
def test_consistent_declared_hardware(
    hardware_input: HardwareInput,
    revision: str | None,
    mcu: str,
    supported: str,
    rejected: str,
) -> None:
    advisory = build_advisory(capture_with_version(), hardware_input)
    assert advisory.hardware_revision == revision and advisory.mcu == mcu
    assert compatibility(advisory, supported) is Compatibility.COMPATIBLE_DECLARED
    assert compatibility(advisory, rejected) is Compatibility.INCOMPATIBLE


def test_conflicting_revision_and_mcu_are_not_resolved() -> None:
    advisory = build_advisory(
        capture_with_version(), HardwareInput(hardware_revision="V3", mcu="DP32G030")
    )
    assert advisory.conflicting
    assert all(item.compatibility is Compatibility.CONFLICTING for item in advisory.entries)


def test_unknown_firmware_string_does_not_change_hardware_advice() -> None:
    advisory = build_advisory(capture_with_version(None))
    assert advisory.observed_firmware is None
    assert advisory.confidence.firmware_version is ScopeConfidence.UNKNOWN
    assert all(item.compatibility is Compatibility.UNKNOWN for item in advisory.entries)


def test_advisory_json_is_stable_and_field_scoped() -> None:
    capture = capture_with_version()
    first = build_advisory(capture, HardwareInput(hardware_revision="V1")).to_dict()
    second = build_advisory(replace(capture), HardwareInput(hardware_revision="V1")).to_dict()
    assert first == second
    assert first["confidence"]["hardware_revision"] == "user-supplied"
    assert first["confidence"]["mcu_family"] == "database-inference"
