from qsidentify.models import Confidence
from qsidentify.protocol.decoder import decode_response


def test_decodes_firmware_string() -> None:
    decoded = decode_response(b"\x00\x01k5_2.01.27\x00")
    assert decoded.reported_version == "k5_2.01.27"
    assert decoded.confidence is Confidence.MEDIUM
    assert decoded.inferred_family is not None


def test_preserves_unknown_response_as_evidence() -> None:
    decoded = decode_response(bytes.fromhex("01020304aabbccdd"))
    assert decoded.reported_version is None
    assert decoded.detected_protocol == "Unknown serial response"
    assert decoded.confidence is Confidence.LOW
    assert decoded.evidence


def test_empty_response() -> None:
    decoded = decode_response(b"")
    assert decoded.confidence is Confidence.NONE
    assert decoded.warnings
