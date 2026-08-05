import pytest

from qsidentify.models import ChecksumStatus
from qsidentify.protocol.commands import IDENTIFY_HANDSHAKE
from qsidentify.protocol.frame import (
    FRAME_FOOTER,
    FRAME_HEADER,
    ChecksumMismatchError,
    InvalidFooterError,
    InvalidHeaderError,
    InvalidLengthError,
    InvalidReservedByteError,
    TruncatedFrameError,
    crc16_xmodem,
    decode_frame,
    encode_frame,
    xor_transform,
)


def test_crc16_xmodem_standard_vector() -> None:
    assert crc16_xmodem(b"123456789") == 0x31C3


def test_crc16_xmodem_empty() -> None:
    assert crc16_xmodem(b"") == 0


def test_crc16_xmodem_identify_payload() -> None:
    assert crc16_xmodem(IDENTIFY_HANDSHAKE.payload) == 0x9C98


def test_xor_known_vector_and_round_trip() -> None:
    source = bytes.fromhex("14 05 04 00 6a 39 57 64")
    transformed = xor_transform(source)
    assert transformed == bytes.fromhex("02 69 10 e6 44 a8 5a 24")
    assert xor_transform(transformed) == source


def test_xor_longer_than_key_cycle() -> None:
    source = bytes(range(64))
    assert xor_transform(xor_transform(source)) == source
    assert xor_transform(source)[:32] != xor_transform(source)[32:]


def test_identification_frame_known_vector() -> None:
    assert IDENTIFY_HANDSHAKE.encoded_frame() == bytes.fromhex(
        "ab cd 08 00 02 69 10 e6 44 a8 5a 24 b9 a9 dc ba"
    )


def test_known_firmware_response_vector() -> None:
    frame = bytes.fromhex("ab cd 0d 00 03 69 7f d3 71 a3 23 70 10 1b e7 77 13 7f c0 dc ba")
    decoded = decode_frame(frame)
    assert decoded.payload == bytes.fromhex("15 05") + b"k5_2.01.27\x00"
    assert decoded.checksum_status is ChecksumStatus.VALID


def test_frame_layout() -> None:
    frame = encode_frame(b"abc")
    assert frame[:2] == FRAME_HEADER
    assert frame[2:4] == b"\x03\x00"
    assert frame[-2:] == FRAME_FOOTER
    decoded = decode_frame(frame)
    assert decoded.payload == b"abc"
    assert decoded.checksum_received == decoded.checksum_calculated
    assert decoded.checksum_status is ChecksumStatus.VALID
    assert decoded.original == frame


def test_legacy_ff_ff_checksum_is_accepted_but_not_verified() -> None:
    payload = bytes.fromhex("18 05") + b"BL1.0\x00"
    protected = xor_transform(payload + b"\xff\xff")
    frame = FRAME_HEADER + len(payload).to_bytes(2, "little") + protected + FRAME_FOOTER
    decoded = decode_frame(frame)
    assert decoded.checksum_status is ChecksumStatus.LEGACY_FF_FF
    assert not decoded.checksum_valid
    assert decoded.checksum_received is None


@pytest.mark.parametrize(
    ("frame", "error"),
    [
        (b"", TruncatedFrameError),
        (b"\xab", TruncatedFrameError),
        (b"bad!", InvalidHeaderError),
        (encode_frame(b"abc")[:-1], TruncatedFrameError),
        (encode_frame(b"abc")[:-2] + b"xx", InvalidFooterError),
        (FRAME_HEADER + b"\x01\xff", InvalidReservedByteError),
        (encode_frame(b"abc") + b"extra", InvalidLengthError),
    ],
)
def test_malformed_frames(frame: bytes, error: type[ValueError]) -> None:
    with pytest.raises(error):
        decode_frame(frame)


def test_checksum_mismatch() -> None:
    frame = bytearray(encode_frame(b"abc"))
    frame[4] ^= 1
    with pytest.raises(ChecksumMismatchError):
        decode_frame(bytes(frame))


def test_payload_larger_than_wire_length_field_is_rejected() -> None:
    with pytest.raises(InvalidLengthError):
        encode_frame(bytes(256))


def test_leading_bytes_are_not_silently_accepted_by_codec() -> None:
    with pytest.raises(InvalidHeaderError):
        decode_frame(b"noise" + encode_frame(b"abc"))
