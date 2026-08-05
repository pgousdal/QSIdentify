import pytest

from qsidentify.models import TransportClassification
from qsidentify.protocol.commands import IDENTIFY_HANDSHAKE
from qsidentify.protocol.frame import FRAME_HEADER, encode_frame
from qsidentify.protocol.stream import analyze_stream

TX = IDENTIFY_HANDSHAKE.encoded_frame()
RESPONSE = encode_frame(b"\x15\x05V1.0\x00")


@pytest.mark.parametrize("prefix", [b"", b"garbage"])
def test_valid_frame_at_any_offset(prefix: bytes) -> None:
    analysis = analyze_stream(prefix + RESPONSE, TX)
    assert analysis.classification is TransportClassification.FRAMED_RESPONSE
    assert analysis.leading_bytes == prefix
    assert analysis.valid_response_frames[0].original == RESPONSE


def test_multiple_valid_frames() -> None:
    second = encode_frame(b"other")
    analysis = analyze_stream(RESPONSE + b"between" + second, TX)
    assert len(analysis.valid_response_frames) == 2
    assert b"between" in analysis.unparsed_bytes


def test_invalid_frame_followed_by_valid_frame() -> None:
    invalid = bytearray(encode_frame(b"bad"))
    invalid[-1] ^= 1
    analysis = analyze_stream(bytes(invalid) + RESPONSE, TX)
    assert any(not item.valid for item in analysis.candidates)
    assert analysis.valid_response_frames[0].original == RESPONSE


def test_invalid_frame_without_following_response_is_classified() -> None:
    invalid = bytearray(RESPONSE)
    invalid[-1] ^= 1
    analysis = analyze_stream(bytes(invalid), TX)
    assert analysis.classification is TransportClassification.INVALID_FRAME


@pytest.mark.parametrize(
    ("data", "classification", "echoes"),
    [
        (TX, TransportClassification.ECHO_ONLY, 1),
        (b"lead" + TX, TransportClassification.TRANSMIT_ECHO, 1),
        (TX + RESPONSE, TransportClassification.ECHO_FOLLOWED_BY_RESPONSE, 1),
        (TX + TX, TransportClassification.ECHO_ONLY, 2),
        (TX[:7], TransportClassification.PARTIAL_TRANSMIT_ECHO, 0),
    ],
)
def test_echo_classification(
    data: bytes, classification: TransportClassification, echoes: int
) -> None:
    analysis = analyze_stream(data, TX)
    assert analysis.classification is classification
    assert len(analysis.echo_frames) == echoes


@pytest.mark.parametrize("data", [FRAME_HEADER[:1], FRAME_HEADER + b"\x08"])
def test_partial_frame_candidates(data: bytes) -> None:
    analysis = analyze_stream(data, TX)
    expected = (
        TransportClassification.PARTIAL_TRANSMIT_ECHO
        if TX.startswith(data)
        else TransportClassification.INCOMPLETE_RESPONSE
    )
    assert analysis.classification is expected


def test_partial_footer_is_incomplete() -> None:
    analysis = analyze_stream(RESPONSE[:-1], TX)
    assert analysis.classification is TransportClassification.INCOMPLETE_RESPONSE


@pytest.mark.parametrize(
    ("data", "classification"),
    [
        (b"", TransportClassification.NO_RESPONSE),
        (b"\x00\x00\x00", TransportClassification.NULL_BYTE_RESPONSE),
        (b"\x00\x20\x02\x29", TransportClassification.UNFRAMED_BINARY_RESPONSE),
    ],
)
def test_unframed_classifications(data: bytes, classification: TransportClassification) -> None:
    assert analyze_stream(data, TX).classification is classification
