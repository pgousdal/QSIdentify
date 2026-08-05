from __future__ import annotations

from . import __version__
from .drivers import Driver, default_driver
from .models import (
    Confidence,
    DecodedResponse,
    Evidence,
    LineSetting,
    MessageType,
    PortInfo,
    ProbeReport,
    ProbeResult,
    SafetyClass,
    TransportClassification,
)
from .transport import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_SETTLE_DELAY,
    DEFAULT_TOTAL_TIMEOUT,
    SerialFactory,
    exchange,
    monitor,
)


def _transport_response(
    result_class: TransportClassification,
    raw: bytes,
    driver: Driver,
    candidate: bytes | None = None,
) -> DecodedResponse:
    evidence = (Evidence("raw-response-hex", raw.hex(), "serial-stream"),) if raw else ()
    if result_class is TransportClassification.NO_RESPONSE:
        return driver.decode(b"")
    if result_class in {
        TransportClassification.ECHO_ONLY,
        TransportClassification.TRANSMIT_ECHO,
    }:
        message = (
            MessageType.ECHO_ONLY
            if result_class is TransportClassification.ECHO_ONLY
            else MessageType.TRANSMIT_ECHO
        )
        return DecodedResponse(
            None,
            None,
            "Serial transmit echo",
            message,
            None,
            Confidence.HIGH,
            evidence,
            ("The encoded transmit frame was received as a serial echo.",),
        )
    if result_class is TransportClassification.PARTIAL_TRANSMIT_ECHO:
        return DecodedResponse(
            None,
            None,
            "Partial serial transmit echo",
            MessageType.PARTIAL_TRANSMIT_ECHO,
            None,
            Confidence.MEDIUM,
            evidence,
            ("A suffix of the response matches the beginning of the transmitted frame.",),
        )
    if result_class is TransportClassification.NULL_BYTE_RESPONSE:
        return DecodedResponse(
            None,
            None,
            "No framed protocol response",
            MessageType.NULL_BYTE_RESPONSE,
            None,
            Confidence.MEDIUM,
            evidence,
            (
                "Only zero bytes were received. This may indicate a cable, connector, "
                "electrical UART-line, baud-rate or incompatible-protocol condition.",
            ),
        )
    if result_class is TransportClassification.INCOMPLETE_RESPONSE:
        return driver.decode(candidate or raw, incomplete=True)
    if result_class is TransportClassification.INVALID_FRAME:
        return driver.decode(candidate or raw)
    return DecodedResponse(
        None,
        None,
        "No framed protocol response",
        MessageType.UNFRAMED_BINARY_RESPONSE,
        None,
        Confidence.LOW,
        evidence,
        ("Unframed binary bytes were preserved without protocol identification.",),
    )


def _result(port: PortInfo, exchange_result, baud_rate: int, driver: Driver) -> ProbeResult:  # type: ignore[no-untyped-def]
    analysis = exchange_result.analysis
    if analysis.valid_response_frames:
        decoded = driver.decode(analysis.valid_response_frames[0].original)
    else:
        candidate = next(
            (item.data for item in analysis.candidates if not item.echo),
            None,
        )
        decoded = _transport_response(
            analysis.classification,
            exchange_result.raw_response,
            driver,
            candidate,
        )
    operating_mode = (
        "firmware-bootloader"
        if decoded.message_type is MessageType.BOOTLOADER_RESPONSE
        else "normal-programming-mode"
        if decoded.frame is not None
        else "unknown"
    )
    report = ProbeReport(
        schema_version=2,
        qsidentify_version=__version__,
        port=port,
        baud_rate=baud_rate,
        timeout=exchange_result.total_timeout,
        idle_timeout=exchange_result.idle_timeout,
        settle_delay=exchange_result.settle_delay,
        transport_classification=analysis.classification,
        operating_mode=operating_mode,
        response_received=bool(exchange_result.raw_response),
        frame_detected=bool(analysis.candidates),
        frame_complete=bool(analysis.valid_response_frames),
        message_type=decoded.message_type,
        reported_version=decoded.reported_version,
        reported_bootloader_version=decoded.reported_bootloader_version,
        detected_protocol=decoded.detected_protocol,
        inferred_family=decoded.inferred_family,
        confidence=decoded.confidence,
        evidence=decoded.evidence,
        warnings=decoded.warnings,
    )
    return ProbeResult(report, exchange_result, decoded, driver.info.id, driver.info.version)


def probe_port(
    port: PortInfo,
    *,
    baud_rate: int = 38400,
    timeout: float = DEFAULT_TOTAL_TIMEOUT,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    settle_delay: float = DEFAULT_SETTLE_DELAY,
    dtr: LineSetting = LineSetting.AUTO,
    rts: LineSetting = LineSetting.AUTO,
    serial_factory: SerialFactory | None = None,
    driver: Driver | None = None,
) -> ProbeResult:
    driver = driver or default_driver()
    command = driver.identify()
    if command.safety is not SafetyClass.READ_ONLY:
        raise RuntimeError("Refusing to transmit a command that is not read-only.")
    kwargs: dict[str, object] = {
        "baud_rate": baud_rate,
        "total_timeout": timeout,
        "idle_timeout": idle_timeout,
        "settle_delay": settle_delay,
        "dtr": dtr,
        "rts": rts,
        "stream_analyzer": driver.analyze_stream,
    }
    if serial_factory is not None:
        kwargs["serial_factory"] = serial_factory
    serial_exchange = exchange(port.device, command.payload, driver.encode(command), **kwargs)
    return _result(port, serial_exchange, baud_rate, driver)


def monitor_port(
    port: PortInfo,
    *,
    baud_rate: int = 38400,
    duration: float = 5.0,
    idle_timeout: float = 1.0,
    dtr: LineSetting = LineSetting.AUTO,
    rts: LineSetting = LineSetting.AUTO,
    serial_factory: SerialFactory | None = None,
    driver: Driver | None = None,
) -> ProbeResult:
    driver = driver or default_driver()
    kwargs: dict[str, object] = {
        "baud_rate": baud_rate,
        "total_timeout": duration,
        "idle_timeout": idle_timeout,
        "settle_delay": 0.0,
        "dtr": dtr,
        "rts": rts,
        "stream_analyzer": driver.analyze_stream,
    }
    if serial_factory is not None:
        kwargs["serial_factory"] = serial_factory
    return _result(port, monitor(port.device, **kwargs), baud_rate, driver)
