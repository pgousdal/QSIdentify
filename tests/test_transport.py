from collections.abc import Iterable
from itertools import repeat

import pytest
import serial

from qsidentify.models import LineSetting, TransportClassification
from qsidentify.protocol.commands import IDENTIFY_HANDSHAKE
from qsidentify.protocol.frame import encode_frame
from qsidentify.transport import (
    ResponseTooLargeError,
    SerialOpenError,
    SerialReadError,
    SerialWriteError,
    collect_stream,
    exchange,
    monitor,
)


class Clock:
    def __init__(self, step: float = 0.01) -> None:
        self.value = 0.0
        self.step = step
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        self.value += self.step
        return self.value

    def sleep(self, value: float) -> None:
        self.sleeps.append(value)


class FakeSerial:
    def __init__(self, chunks: Iterable[bytes | Exception]) -> None:
        self.chunks = iter(chunks)
        self.writes: list[bytes] = []
        self.input_reset = False
        self.output_reset = False
        self.flushed = False
        self.closed = False
        self.dtr = True
        self.rts = True

    def reset_input_buffer(self) -> None:
        self.input_reset = True

    def reset_output_buffer(self) -> None:
        self.output_reset = True

    def write(self, data: bytes) -> int:
        self.writes.append(data)
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
        assert len(item) <= size
        return item

    def close(self) -> None:
        self.closed = True


def factory(fake: FakeSerial):
    def create(**_kwargs: object) -> FakeSerial:
        return fake

    return create


def run_exchange(fake: FakeSerial, *, clock: Clock | None = None, **kwargs: object):
    timer = clock or Clock()
    command = IDENTIFY_HANDSHAKE
    return exchange(
        "test",
        command.payload,
        command.encoded_frame(),
        total_timeout=1.0,
        idle_timeout=0.05,
        settle_delay=0.1,
        serial_factory=factory(fake),
        monotonic=timer.monotonic,
        sleep=timer.sleep,
        **kwargs,
    )


@pytest.mark.parametrize(
    "chunks",
    [
        lambda response: [response],
        lambda response: [bytes((octet,)) for octet in response],
        lambda response: [response[index : index + 4] for index in range(0, len(response), 4)],
    ],
)
def test_response_chunking_is_preserved(chunks) -> None:  # type: ignore[no-untyped-def]
    response = encode_frame(b"response")
    result = run_exchange(FakeSerial(chunks(response)))
    assert result.raw_response == response
    assert b"".join(item.data for item in result.chunks) == response
    assert result.analysis.valid_response_frames[0].original == response


def test_leading_garbage_echo_and_following_response() -> None:
    tx = IDENTIFY_HANDSHAKE.encoded_frame()
    response = encode_frame(b"response")
    result = run_exchange(FakeSerial([b"junk", tx, response]))
    assert result.analysis.leading_bytes == b"junk"
    assert result.analysis.echo_frames == (tx,)
    assert result.analysis.classification is TransportClassification.ECHO_FOLLOWED_BY_RESPONSE


@pytest.mark.parametrize(
    ("response", "classification"),
    [
        (IDENTIFY_HANDSHAKE.encoded_frame(), TransportClassification.ECHO_ONLY),
        (IDENTIFY_HANDSHAKE.encoded_frame()[:8], TransportClassification.PARTIAL_TRANSMIT_ECHO),
        (b"\x00\x00\x00", TransportClassification.NULL_BYTE_RESPONSE),
        (b"\x00\x20\x02\x29", TransportClassification.UNFRAMED_BINARY_RESPONSE),
    ],
)
def test_transport_classifications(
    response: bytes, classification: TransportClassification
) -> None:
    assert run_exchange(FakeSerial([response])).analysis.classification is classification


def test_no_bytes_returns_empty_exchange_at_total_timeout() -> None:
    result = run_exchange(FakeSerial([]))
    assert not result.raw_response
    assert result.analysis.classification is TransportClassification.NO_RESPONSE


def test_idle_timeout_returns_partial_data() -> None:
    result = run_exchange(FakeSerial([b"partial"]))
    assert result.raw_response == b"partial"
    assert result.analysis.classification is TransportClassification.UNFRAMED_BINARY_RESPONSE


def test_total_timeout_bounds_continuous_input_and_returns_collected_prefix() -> None:
    clock = Clock(step=0.1)
    result = run_exchange(FakeSerial(repeat(b"x")), clock=clock)
    assert result.raw_response
    assert len(result.raw_response) < 10


def test_response_size_limit() -> None:
    with pytest.raises(ResponseTooLargeError):
        run_exchange(FakeSerial([b"1234", b"5"]), max_response_size=4)


def test_line_state_and_settle_delay_are_applied_once() -> None:
    fake = FakeSerial([])
    clock = Clock()
    result = run_exchange(
        fake, clock=clock, dtr=LineSetting.OFF, rts=LineSetting.ON
    )
    assert result.line_state.dtr is False and result.line_state.rts is True
    assert fake.dtr is False and fake.rts is True
    assert clock.sleeps == [0.1]
    assert fake.input_reset and fake.output_reset


def test_monitor_performs_zero_writes() -> None:
    fake = FakeSerial([b"spontaneous", b"-data"])
    clock = Clock()
    result = monitor(
        "test",
        total_timeout=0.3,
        idle_timeout=0.05,
        settle_delay=0,
        serial_factory=factory(fake),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    assert fake.writes == []
    assert result.raw_response == b"spontaneous-data"
    assert len(result.chunks) == 2


def test_serial_failures_are_classified() -> None:
    def broken_factory(**_kwargs: object) -> FakeSerial:
        raise serial.SerialException("open")

    with pytest.raises(SerialOpenError):
        collect_stream("test", serial_factory=broken_factory)
    with pytest.raises(SerialReadError):
        run_exchange(FakeSerial([serial.SerialException("read")]))

    class BrokenWrite(FakeSerial):
        def write(self, data: bytes) -> int:
            raise serial.SerialException("write")

    with pytest.raises(SerialWriteError):
        run_exchange(BrokenWrite([]))


def test_invalid_timing_values() -> None:
    with pytest.raises(ValueError):
        collect_stream("test", total_timeout=0.1, idle_timeout=0.2)
