from __future__ import annotations

from . import __version__
from .models import PortInfo, ProbeReport, ProbeResult
from .protocol.commands import IDENTIFY_HANDSHAKE, SafetyClass
from .protocol.decoder import decode_response
from .transport import exchange


def probe_port(
    port: PortInfo,
    *,
    baud_rate: int = 38400,
    timeout: float = 1.0,
) -> ProbeResult:
    command = IDENTIFY_HANDSHAKE
    if command.safety is not SafetyClass.READ_ONLY:
        raise RuntimeError("Refusing to transmit a command that is not read-only.")

    serial_exchange = exchange(
        port.device,
        command.payload,
        baud_rate=baud_rate,
        timeout=timeout,
    )
    decoded = decode_response(serial_exchange.response)

    report = ProbeReport(
        schema_version=1,
        qsidentify_version=__version__,
        port=port,
        baud_rate=baud_rate,
        operating_mode=(
            "normal-programming-mode"
            if serial_exchange.response
            else "unknown-or-no-response"
        ),
        response_received=bool(serial_exchange.response),
        reported_version=decoded.reported_version,
        detected_protocol=decoded.detected_protocol,
        inferred_family=decoded.inferred_family,
        confidence=decoded.confidence,
        evidence=decoded.evidence,
        warnings=decoded.warnings,
    )
    return ProbeResult(report=report, exchange=serial_exchange)
