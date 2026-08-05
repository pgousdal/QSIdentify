from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol, cast

import serial

from .models import Exchange, LineSetting, LineState, ReadChunk
from .protocol.stream import analyze_stream

DEFAULT_BAUD_RATE = 38400
DEFAULT_SETTLE_DELAY = 0.10
DEFAULT_TOTAL_TIMEOUT = 3.0
DEFAULT_IDLE_TIMEOUT = 0.20
DEFAULT_MAX_RESPONSE_SIZE = 4096
READ_SIZE = 64


class TransportError(RuntimeError):
    pass


class NoResponseError(TransportError):
    """Compatibility exception; stream collection now returns empty evidence."""


class IncompleteHeaderError(TransportError):
    pass


class IncompleteFrameError(TransportError):
    pass


class InvalidDeclaredLengthError(TransportError):
    pass


class ResponseTooLargeError(TransportError):
    pass


class SerialOpenError(TransportError):
    pass


class SerialWriteError(TransportError):
    pass


class SerialReadError(TransportError):
    pass


class SerialConnection(Protocol):
    dtr: bool
    rts: bool

    def reset_input_buffer(self) -> None: ...
    def reset_output_buffer(self) -> None: ...
    def write(self, data: bytes) -> int | None: ...
    def flush(self) -> None: ...
    def read(self, size: int = 1) -> bytes: ...
    def close(self) -> None: ...


SerialFactory = Callable[..., SerialConnection]


def _default_serial_factory(**kwargs: object) -> SerialConnection:
    return cast(SerialConnection, serial.Serial(**kwargs))  # type: ignore[arg-type]


def _validate_settings(
    *,
    baud_rate: int,
    settle_delay: float,
    total_timeout: float,
    idle_timeout: float,
    max_response_size: int,
) -> None:
    if baud_rate <= 0 or total_timeout <= 0 or idle_timeout <= 0 or max_response_size <= 0:
        raise ValueError("baud_rate, timeouts and maximum response size must be positive")
    if settle_delay < 0:
        raise ValueError("settle_delay must be non-negative")
    if idle_timeout > total_timeout:
        raise ValueError("idle_timeout cannot exceed total_timeout")


def _apply_line_setting(
    connection: SerialConnection, attribute: str, setting: LineSetting
) -> bool | None:
    if setting is LineSetting.AUTO:
        value = getattr(connection, attribute, None)
        return value if isinstance(value, bool) else None
    value = setting is LineSetting.ON
    setattr(connection, attribute, value)
    return value


def collect_stream(
    device: str,
    *,
    request_payload: bytes = b"",
    request_frame: bytes = b"",
    operation: str = "monitor",
    baud_rate: int = DEFAULT_BAUD_RATE,
    settle_delay: float = DEFAULT_SETTLE_DELAY,
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    dtr: LineSetting = LineSetting.AUTO,
    rts: LineSetting = LineSetting.AUTO,
    max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
    serial_factory: SerialFactory = _default_serial_factory,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Exchange:
    _validate_settings(
        baud_rate=baud_rate,
        settle_delay=settle_delay,
        total_timeout=total_timeout,
        idle_timeout=idle_timeout,
        max_response_size=max_response_size,
    )
    if operation not in {"probe", "monitor"}:
        raise ValueError("operation must be probe or monitor")
    if operation == "monitor" and (request_payload or request_frame):
        raise ValueError("monitor operation cannot contain transmit bytes")
    try:
        connection = serial_factory(
            port=device,
            baudrate=baud_rate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=min(idle_timeout, total_timeout, 0.05),
            write_timeout=total_timeout,
        )
    except (serial.SerialException, OSError) as exc:
        raise SerialOpenError(f"Could not open serial port: {exc}") from exc

    try:
        line_state = LineState(
            dtr=_apply_line_setting(connection, "dtr", dtr),
            rts=_apply_line_setting(connection, "rts", rts),
        )
        try:
            connection.reset_input_buffer()
            connection.reset_output_buffer()
            if settle_delay:
                sleep(settle_delay)
            if request_frame:
                written = connection.write(request_frame)
                if written is not None and written != len(request_frame):
                    raise SerialWriteError(
                        f"Serial write was incomplete: {written} of {len(request_frame)} bytes."
                    )
                connection.flush()
        except SerialWriteError:
            raise
        except (serial.SerialException, OSError) as exc:
            raise SerialWriteError(f"Serial setup or write failed: {exc}") from exc

        start = monotonic()
        total_deadline = start + total_timeout
        last_received: float | None = None
        chunks: list[ReadChunk] = []
        raw = bytearray()
        while True:
            now = monotonic()
            if now >= total_deadline:
                break
            if last_received is not None and now - last_received >= idle_timeout:
                break
            try:
                chunk = connection.read(min(READ_SIZE, max_response_size - len(raw) + 1))
            except (serial.SerialException, OSError) as exc:
                raise SerialReadError(f"Serial read failed: {exc}") from exc
            if not chunk:
                continue
            received_at = monotonic()
            raw.extend(chunk)
            if len(raw) > max_response_size:
                raise ResponseTooLargeError(f"Serial response exceeded {max_response_size} bytes.")
            chunks.append(
                ReadChunk(
                    sequence=len(chunks) + 1,
                    monotonic_offset_ms=round((received_at - start) * 1000, 3),
                    data=bytes(chunk),
                )
            )
            last_received = received_at

        response = bytes(raw)
        return Exchange(
            request_payload=request_payload,
            request_frame=request_frame,
            chunks=tuple(chunks),
            raw_response=response,
            analysis=analyze_stream(response, request_frame),
            line_state=line_state,
            settle_delay=settle_delay,
            total_timeout=total_timeout,
            idle_timeout=idle_timeout,
            dtr_setting=dtr,
            rts_setting=rts,
            operation=operation,
        )
    finally:
        connection.close()


def exchange(
    device: str,
    logical_request: bytes,
    transmitted_frame: bytes,
    **kwargs: object,
) -> Exchange:
    return collect_stream(
        device,
        request_payload=logical_request,
        request_frame=transmitted_frame,
        operation="probe",
        **kwargs,  # type: ignore[arg-type]
    )


def monitor(device: str, **kwargs: object) -> Exchange:
    return collect_stream(device, operation="monitor", **kwargs)  # type: ignore[arg-type]
