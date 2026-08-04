from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol, cast

import serial

from .models import Exchange
from .protocol.frame import FRAME_HEADER, HEADER_SIZE, MAX_PAYLOAD_SIZE, frame_size_from_header


class TransportError(RuntimeError):
    pass


class NoResponseError(TransportError):
    pass


class IncompleteHeaderError(TransportError):
    def __init__(self, leading: bytes, received: bytes) -> None:
        super().__init__("Timed out after receiving an incomplete frame header.")
        self.leading = leading
        self.received = received


class IncompleteFrameError(TransportError):
    def __init__(self, leading: bytes, received: bytes, expected_size: int) -> None:
        super().__init__(f"Timed out after {len(received)} of {expected_size} frame bytes.")
        self.leading = leading
        self.received = received
        self.expected_size = expected_size


class InvalidDeclaredLengthError(TransportError):
    pass


class SerialOpenError(TransportError):
    pass


class SerialWriteError(TransportError):
    pass


class SerialReadError(TransportError):
    pass


class SerialConnection(Protocol):
    def reset_input_buffer(self) -> None: ...
    def write(self, data: bytes) -> int | None: ...
    def flush(self) -> None: ...
    def read(self, size: int = 1) -> bytes: ...
    def close(self) -> None: ...


SerialFactory = Callable[..., SerialConnection]


def _default_serial_factory(**kwargs: object) -> SerialConnection:
    return cast(SerialConnection, serial.Serial(**kwargs))  # type: ignore[arg-type]


def exchange(
    device: str,
    logical_request: bytes,
    transmitted_frame: bytes,
    *,
    baud_rate: int = 38400,
    timeout: float = 1.0,
    max_payload_size: int = MAX_PAYLOAD_SIZE,
    serial_factory: SerialFactory = _default_serial_factory,
) -> Exchange:
    if timeout <= 0 or baud_rate <= 0 or max_payload_size <= 0:
        raise ValueError("baud_rate, timeout and max_payload_size must be positive")
    try:
        connection = serial_factory(
            port=device,
            baudrate=baud_rate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=min(timeout, 0.05),
            write_timeout=timeout,
        )
    except (serial.SerialException, OSError) as exc:
        raise SerialOpenError(f"Could not open serial port: {exc}") from exc

    try:
        try:
            connection.reset_input_buffer()
            written = connection.write(transmitted_frame)
            if written is not None and written != len(transmitted_frame):
                raise SerialWriteError(
                    f"Serial write was incomplete: {written} of {len(transmitted_frame)} bytes."
                )
            connection.flush()
        except SerialWriteError:
            raise
        except (serial.SerialException, OSError) as exc:
            raise SerialWriteError(f"Serial write failed: {exc}") from exc

        deadline = time.monotonic() + timeout
        buffer = bytearray()
        header_index = -1
        try:
            while time.monotonic() < deadline:
                chunk = connection.read(1)
                if not chunk:
                    continue
                buffer.extend(chunk)
                header_index = buffer.find(FRAME_HEADER)
                if header_index >= 0:
                    break
        except (serial.SerialException, OSError) as exc:
            raise SerialReadError(f"Serial read failed: {exc}") from exc
        if header_index < 0:
            if not buffer:
                raise NoResponseError("No response was received before timeout.")
            if buffer.endswith(FRAME_HEADER[:1]):
                raise IncompleteHeaderError(bytes(buffer[:-1]), bytes(buffer[-1:]))
            return Exchange(logical_request, transmitted_frame, bytes(buffer), b"")

        leading = bytes(buffer[:header_index])
        frame = bytearray(buffer[header_index:])
        try:
            while len(frame) < HEADER_SIZE and time.monotonic() < deadline:
                frame.extend(connection.read(HEADER_SIZE - len(frame)))
        except (serial.SerialException, OSError) as exc:
            raise SerialReadError(f"Serial read failed: {exc}") from exc
        if len(frame) < HEADER_SIZE:
            raise IncompleteHeaderError(leading, bytes(frame))
        try:
            expected_size = frame_size_from_header(
                bytes(frame[:HEADER_SIZE]), max_payload_size=max_payload_size
            )
        except ValueError as exc:
            raise InvalidDeclaredLengthError(str(exc)) from exc
        try:
            while len(frame) < expected_size and time.monotonic() < deadline:
                frame.extend(connection.read(expected_size - len(frame)))
        except (serial.SerialException, OSError) as exc:
            raise SerialReadError(f"Serial read failed: {exc}") from exc
        if len(frame) < expected_size:
            raise IncompleteFrameError(leading, bytes(frame), expected_size)
        return Exchange(logical_request, transmitted_frame, leading, bytes(frame))
    finally:
        connection.close()
