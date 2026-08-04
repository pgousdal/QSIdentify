from __future__ import annotations

import re

from qsidentify.models import Confidence, DecodedResponse, Evidence, MessageType
from qsidentify.protocol.frame import FrameError, decode_frame

_PRINTABLE = re.compile(rb"[ -~]{3,}")
_VERSION_NUMBER = re.compile(r"\d+(?:\.\d+)+")
_VERSION_HINT = re.compile(
    r"(?:k5[_ -]?)?v?\d+(?:\.\d+){1,3}|k5_\d+(?:\.\d+){1,3}|"
    r"(?:egzumer|f4hwn|ijv)[ -~]{0,32}",
    re.IGNORECASE,
)
_BOOTLOADER_MESSAGE = bytes.fromhex("18 05")


def extract_printable_strings(payload: bytes) -> tuple[str, ...]:
    return tuple(match.group().decode("ascii") for match in _PRINTABLE.finditer(payload))


def _response(
    *,
    message_type: MessageType,
    warnings: tuple[str, ...],
    evidence: tuple[Evidence, ...] = (),
    confidence: Confidence = Confidence.NONE,
    detected_protocol: str | None = None,
) -> DecodedResponse:
    return DecodedResponse(
        reported_version=None,
        reported_bootloader_version=None,
        detected_protocol=detected_protocol,
        message_type=message_type,
        inferred_family=None,
        confidence=confidence,
        evidence=evidence,
        warnings=warnings,
    )


def decode_response(data: bytes, *, incomplete: bool = False) -> DecodedResponse:
    if not data:
        return _response(
            message_type=MessageType.NO_RESPONSE,
            warnings=("No response bytes were received.",),
        )
    if incomplete:
        return _response(
            message_type=MessageType.INCOMPLETE_RESPONSE,
            warnings=("The response ended before a complete frame was received.",),
            evidence=(Evidence("raw-response-hex", data.hex(), "serial-response"),),
        )
    if not data.startswith(bytes.fromhex("ab cd")):
        return _response(
            message_type=MessageType.UNKNOWN_SERIAL_RESPONSE,
            warnings=("Bytes were received, but no Quansheng frame header was found.",),
            evidence=(Evidence("raw-response-hex", data.hex(), "serial-response"),),
            confidence=Confidence.LOW,
            detected_protocol="Unknown serial response",
        )
    try:
        frame = decode_frame(data)
    except FrameError as exc:
        return _response(
            message_type=MessageType.INVALID_FRAME,
            warnings=(str(exc),),
            evidence=(Evidence("invalid-frame-hex", data.hex(), "serial-response"),),
        )

    strings = extract_printable_strings(frame.payload)
    evidence = [
        Evidence("frame-hex", frame.original.hex(), "decoded-frame"),
        Evidence("payload-hex", frame.payload.hex(), "decoded-frame"),
        Evidence("checksum-status", frame.checksum_status.value, "decoded-frame"),
    ]
    evidence.extend(Evidence("printable-string", value, "decoded-payload") for value in strings)
    checksum_warning = (
        ("The response used the accepted legacy FF FF checksum marker; CRC was not verified.",)
        if frame.checksum_received is None
        else ()
    )

    if frame.payload.startswith(_BOOTLOADER_MESSAGE):
        bootloader_version = next(
            (value.strip() for value in strings if _VERSION_NUMBER.search(value)), None
        )
        return DecodedResponse(
            reported_version=None,
            reported_bootloader_version=bootloader_version,
            detected_protocol="Quansheng bootloader response",
            message_type=MessageType.BOOTLOADER_RESPONSE,
            inferred_family=None,
            confidence=Confidence.HIGH if frame.checksum_valid else Confidence.MEDIUM,
            evidence=tuple(evidence),
            warnings=checksum_warning,
            frame=frame,
        )

    version: str | None = None
    for value in strings:
        match = _VERSION_HINT.search(value)
        if match:
            version = match.group().strip().rstrip(" \x00")
            break
    if version is not None:
        lowered = version.lower()
        family = None
        confidence = Confidence.LOW
        if lowered.startswith("k5_"):
            family = "Quansheng K5-compatible protocol family"
            confidence = Confidence.MEDIUM
        elif any(name in lowered for name in ("egzumer", "f4hwn", "ijv")):
            family = "Quansheng K5-compatible custom-firmware family"
            confidence = Confidence.MEDIUM
        return DecodedResponse(
            reported_version=version,
            reported_bootloader_version=None,
            detected_protocol="Quansheng framed identification response",
            message_type=MessageType.FIRMWARE_IDENTIFICATION,
            inferred_family=family,
            confidence=confidence,
            evidence=tuple(evidence),
            warnings=checksum_warning
            + ("A firmware string does not uniquely identify the hardware revision.",),
            frame=frame,
        )

    return DecodedResponse(
        reported_version=None,
        reported_bootloader_version=None,
        detected_protocol="Quansheng framed response",
        message_type=MessageType.VALID_UNKNOWN_FRAME,
        inferred_family=None,
        confidence=Confidence.LOW,
        evidence=tuple(evidence),
        warnings=checksum_warning + ("Valid frame received, but its payload is not recognized.",),
        frame=frame,
    )
