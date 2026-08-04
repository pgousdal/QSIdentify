from __future__ import annotations

from collections.abc import Callable

from . import __version__
from .models import Exchange, MessageType, PortInfo, ProbeReport, ProbeResult, SafetyClass
from .protocol.commands import IDENTIFY_HANDSHAKE
from .protocol.decoder import decode_response
from .transport import (
    IncompleteFrameError,
    IncompleteHeaderError,
    NoResponseError,
    SerialFactory,
    exchange,
)

Transport = Callable[..., object]


def probe_port(
    port: PortInfo,
    *,
    baud_rate: int = 38400,
    timeout: float = 1.0,
    serial_factory: SerialFactory | None = None,
) -> ProbeResult:
    command = IDENTIFY_HANDSHAKE
    if command.safety is not SafetyClass.READ_ONLY:
        raise RuntimeError("Refusing to transmit a command that is not read-only.")
    encoded = command.encoded_frame()
    kwargs: dict[str, object] = {"baud_rate": baud_rate, "timeout": timeout}
    if serial_factory is not None:
        kwargs["serial_factory"] = serial_factory
    try:
        serial_exchange = exchange(
            port.device, command.payload, encoded, **kwargs  # type: ignore[arg-type]
        )
        decoded = decode_response(serial_exchange.received_frame or serial_exchange.leading_bytes)
    except NoResponseError:
        serial_exchange = Exchange(command.payload, encoded, b"", b"", complete=False)
        decoded = decode_response(b"")
    except IncompleteHeaderError as exc:
        serial_exchange = Exchange(
            command.payload, encoded, exc.leading, exc.received, complete=False
        )
        decoded = decode_response(exc.leading + exc.received, incomplete=True)
    except IncompleteFrameError as exc:
        serial_exchange = Exchange(
            command.payload,
            encoded,
            exc.leading,
            exc.received,
            expected_frame_size=exc.expected_size,
            complete=False,
        )
        decoded = decode_response(exc.received, incomplete=True)
    operating_mode = (
        "firmware-bootloader"
        if decoded.message_type is MessageType.BOOTLOADER_RESPONSE
        else "normal-programming-mode"
        if decoded.frame is not None
        else "unknown"
    )
    report = ProbeReport(
        schema_version=1,
        qsidentify_version=__version__,
        port=port,
        baud_rate=baud_rate,
        timeout=timeout,
        operating_mode=operating_mode,
        response_received=bool(serial_exchange.response),
        frame_detected=serial_exchange.received_frame.startswith(bytes.fromhex("ab cd")),
        frame_complete=decoded.frame is not None,
        message_type=decoded.message_type,
        reported_version=decoded.reported_version,
        reported_bootloader_version=decoded.reported_bootloader_version,
        detected_protocol=decoded.detected_protocol,
        inferred_family=decoded.inferred_family,
        confidence=decoded.confidence,
        evidence=decoded.evidence,
        warnings=decoded.warnings,
    )
    return ProbeResult(report=report, exchange=serial_exchange, decoded=decoded)
