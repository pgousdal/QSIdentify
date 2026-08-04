from collections.abc import Iterable

import pytest
import serial

from qsidentify.protocol.frame import FRAME_HEADER, encode_frame
from qsidentify.transport import (
    IncompleteFrameError,
    IncompleteHeaderError,
    InvalidDeclaredLengthError,
    NoResponseError,
    SerialOpenError,
    SerialReadError,
    SerialWriteError,
    exchange,
)


class FakeSerial:
    def __init__(self, chunks: Iterable[bytes | Exception]) -> None:
        self.chunks = iter(chunks)
        self.written = b""
        self.reset = False
        self.flushed = False
        self.closed = False

    def reset_input_buffer(self) -> None:
        self.reset = True

    def write(self, data: bytes) -> int:
        self.written = data
        return len(data)

    def flush(self) -> None:
        self.flushed = True

    def read(self, size: int = 1) -> bytes:
        try:
            item = next(self.chunks)
        except StopIteration:
            return b""
        if isinstance(item, Exception):
            raise item
        if len(item) > size:
            raise AssertionError("test chunk exceeds requested read size")
        return item

    def close(self) -> None:
        self.closed = True


def factory(fake: FakeSerial):
    def create(**_kwargs: object) -> FakeSerial:
        return fake
    return create


def test_complete_response_and_partial_reads() -> None:
    request = encode_frame(b"request")
    response = encode_frame(b"response")
    fake = FakeSerial(bytes([value]) for value in response)
    result = exchange("test", b"request", request, timeout=0.1, serial_factory=factory(fake))
    assert result.received_frame == response
    assert fake.written == request
    assert fake.reset and fake.flushed and fake.closed


def test_leading_garbage_is_preserved() -> None:
    response = encode_frame(b"ok")
    fake = FakeSerial(bytes([value]) for value in b"junk" + response)
    result = exchange("test", b"q", encode_frame(b"q"), timeout=0.1, serial_factory=factory(fake))
    assert result.leading_bytes == b"junk"
    assert result.received_frame == response


def test_timeout_before_header() -> None:
    fake = FakeSerial([])
    with pytest.raises(NoResponseError):
        exchange("test", b"q", encode_frame(b"q"), timeout=0.001, serial_factory=factory(fake))


def test_incomplete_header() -> None:
    fake = FakeSerial([b"\xab"])
    with pytest.raises(IncompleteHeaderError):
        exchange("test", b"q", encode_frame(b"q"), timeout=0.001, serial_factory=factory(fake))


def test_incomplete_frame() -> None:
    response = encode_frame(b"response")[:-2]
    fake = FakeSerial(bytes([value]) for value in response)
    with pytest.raises(IncompleteFrameError):
        exchange("test", b"q", encode_frame(b"q"), timeout=0.005, serial_factory=factory(fake))


def test_strict_maximum_frame_length() -> None:
    header = FRAME_HEADER + (100).to_bytes(2, "little")
    fake = FakeSerial(bytes([value]) for value in header)
    with pytest.raises(InvalidDeclaredLengthError):
        exchange(
            "test", b"q", encode_frame(b"q"), timeout=0.1, max_payload_size=10,
            serial_factory=factory(fake),
        )


def test_serial_open_and_read_errors() -> None:
    def broken_factory(**_kwargs: object) -> FakeSerial:
        raise serial.SerialException("open")
    with pytest.raises(SerialOpenError):
        exchange("test", b"q", encode_frame(b"q"), serial_factory=broken_factory)
    fake = FakeSerial([serial.SerialException("read")])
    with pytest.raises(SerialReadError):
        exchange("test", b"q", encode_frame(b"q"), serial_factory=factory(fake))


def test_serial_write_error_and_short_write() -> None:
    class BrokenWriteSerial(FakeSerial):
        def write(self, data: bytes) -> int:
            raise serial.SerialException("write")

    with pytest.raises(SerialWriteError):
        exchange(
            "test",
            b"q",
            encode_frame(b"q"),
            serial_factory=factory(BrokenWriteSerial([])),
        )
    short = FakeSerial([])
    short.write = lambda data: len(data) - 1  # type: ignore[method-assign]
    with pytest.raises(SerialWriteError):
        exchange("test", b"q", encode_frame(b"q"), serial_factory=factory(short))
