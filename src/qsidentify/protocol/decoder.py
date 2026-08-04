from __future__ import annotations

import re
from dataclasses import dataclass

from qsidentify.models import Confidence, Evidence

_PRINTABLE = re.compile(rb"[ -~]{3,}")
_VERSION_HINT = re.compile(
    r"(?:k5[_ -]?)?v?\d+(?:\.\d+){1,3}|"
    r"k5_\d+(?:\.\d+){1,3}|"
    r"(?:egzumer|f4hwn|ijv)[^\x00\r\n]{0,32}",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class DecodedResponse:
    reported_version: str | None
    detected_protocol: str | None
    inferred_family: str | None
    confidence: Confidence
    evidence: tuple[Evidence, ...]
    warnings: tuple[str, ...]


def _extract_strings(data: bytes) -> tuple[str, ...]:
    return tuple(match.group(0).decode("ascii", errors="replace") for match in _PRINTABLE.finditer(data))


def decode_response(data: bytes) -> DecodedResponse:
    if not data:
        return DecodedResponse(
            reported_version=None,
            detected_protocol=None,
            inferred_family=None,
            confidence=Confidence.NONE,
            evidence=(),
            warnings=("No response bytes were received.",),
        )

    strings = _extract_strings(data)
    evidence = [
        Evidence(kind="response-length", value=str(len(data)), source="serial-response"),
        Evidence(kind="response-hex-prefix", value=data[:16].hex(), source="serial-response"),
    ]
    evidence.extend(
        Evidence(kind="printable-string", value=value, source="serial-response")
        for value in strings
    )

    version: str | None = None
    for value in strings:
        match = _VERSION_HINT.search(value)
        if match:
            version = match.group(0).strip()
            break

    if version:
        lowered = version.lower()
        family = "Quansheng UV-K5-compatible family"
        if "egzumer" in lowered:
            family = "Egzumer firmware on K5-compatible hardware"
        elif "f4hwn" in lowered:
            family = "F4HWN firmware on K5-compatible hardware"
        elif "ijv" in lowered:
            family = "IJV firmware on K5-compatible hardware"

        return DecodedResponse(
            reported_version=version,
            detected_protocol="Quansheng-compatible identification response",
            inferred_family=family,
            confidence=Confidence.MEDIUM,
            evidence=tuple(evidence),
            warnings=(
                "A firmware string does not uniquely identify the hardware revision.",
            ),
        )

    return DecodedResponse(
        reported_version=None,
        detected_protocol="Unknown serial response",
        inferred_family=None,
        confidence=Confidence.LOW,
        evidence=tuple(evidence),
        warnings=(
            "Response captured, but no supported firmware string was recognized.",
        ),
    )
