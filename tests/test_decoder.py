import pytest

from qsidentify.models import Confidence, MessageType
from qsidentify.protocol.decoder import decode_response
from qsidentify.protocol.frame import FRAME_FOOTER, FRAME_HEADER, encode_frame, xor_transform


@pytest.mark.parametrize(
    "version",
    ["k5_2.01.23", "k5_2.01.27", "V1.0", "EGZUMER v0.22", "F4HWN v3.3", "IJV 3.40"],
)
def test_firmware_strings_are_extracted_from_payload(version: str) -> None:
    decoded = decode_response(encode_frame(b"\x15\x05" + version.encode() + b"\x00"))
    assert decoded.reported_version == version
    assert decoded.message_type is MessageType.FIRMWARE_IDENTIFICATION
    assert decoded.frame is not None


def test_generic_version_does_not_infer_hardware() -> None:
    decoded = decode_response(encode_frame(b"\x15\x05V1.0\x00"))
    assert decoded.reported_version == "V1.0"
    assert decoded.inferred_family is None
    assert decoded.confidence is Confidence.LOW


def test_bootloader_response() -> None:
    decoded = decode_response(encode_frame(bytes.fromhex("18 05") + b"BL1.2\x00"))
    assert decoded.message_type is MessageType.BOOTLOADER_RESPONSE
    assert decoded.reported_bootloader_version == "BL1.2"
    assert decoded.reported_version is None


def test_bootloader_without_version_does_not_invent_one() -> None:
    decoded = decode_response(encode_frame(bytes.fromhex("18 05 00 01")))
    assert decoded.message_type is MessageType.BOOTLOADER_RESPONSE
    assert decoded.reported_bootloader_version is None


def test_bootloader_status_text_is_not_mislabeled_as_a_version() -> None:
    decoded = decode_response(encode_frame(bytes.fromhex("18 05") + b"READY\x00"))
    assert decoded.message_type is MessageType.BOOTLOADER_RESPONSE
    assert decoded.reported_bootloader_version is None


@pytest.mark.parametrize("payload", [b"\x01\x02\x03\x04", b"binary\x00only"])
def test_valid_unknown_payload(payload: bytes) -> None:
    decoded = decode_response(encode_frame(payload))
    assert decoded.message_type is MessageType.VALID_UNKNOWN_FRAME
    assert decoded.evidence


def test_no_response_and_incomplete_response() -> None:
    assert decode_response(b"").message_type is MessageType.NO_RESPONSE
    incomplete = decode_response(b"\xab\xcd\x08", incomplete=True)
    assert incomplete.message_type is MessageType.INCOMPLETE_RESPONSE
    assert incomplete.evidence[0].value == "abcd08"


def test_unknown_serial_and_invalid_frame() -> None:
    assert decode_response(b"garbage").message_type is MessageType.UNKNOWN_SERIAL_RESPONSE
    assert decode_response(encode_frame(b"x")[:-1]).message_type is MessageType.INVALID_FRAME


def test_legacy_checksum_warning() -> None:
    payload = b"\x15\x05V1.0\x00"
    frame = (
        FRAME_HEADER
        + len(payload).to_bytes(2, "little")
        + xor_transform(payload + b"\xff\xff")
        + FRAME_FOOTER
    )
    decoded = decode_response(frame)
    assert any("legacy FF FF" in warning for warning in decoded.warnings)
