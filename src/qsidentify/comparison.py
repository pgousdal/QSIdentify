from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .models import Capture


@dataclass(frozen=True, slots=True)
class CaptureSummary:
    response_length: int
    sha256: str
    classification: str
    framed: bool
    echo_present: bool
    null_percentage: float


@dataclass(frozen=True, slots=True)
class Comparison:
    summaries: tuple[CaptureSummary, ...]
    exact_match: bool
    common_prefix: bytes
    common_suffix: bytes
    common_positions: tuple[tuple[int, int], ...]
    byte_frequency: tuple[tuple[int, int], ...]


def _common_prefix(values: tuple[bytes, ...]) -> bytes:
    if not values:
        return b""
    size = min(map(len, values))
    index = 0
    while index < size and len({value[index] for value in values}) == 1:
        index += 1
    return values[0][:index]


def _common_suffix(values: tuple[bytes, ...]) -> bytes:
    reversed_values = tuple(value[::-1] for value in values)
    return _common_prefix(reversed_values)[::-1]


def compare_captures(captures: tuple[Capture, ...]) -> Comparison:
    if len(captures) < 2:
        raise ValueError("At least two captures are required for comparison.")
    responses = tuple(bytes.fromhex(item.raw_response_hex) for item in captures)
    summaries = tuple(
        CaptureSummary(
            response_length=len(response),
            sha256=hashlib.sha256(response).hexdigest(),
            classification=capture.stream_classification.value,
            framed=bool(capture.decoded_valid_frames_hex),
            echo_present=bool(capture.echo_frames_hex),
            null_percentage=(response.count(0) * 100 / len(response)) if response else 0.0,
        )
        for capture, response in zip(captures, responses, strict=True)
    )
    common_positions = tuple(
        (index, responses[0][index])
        for index in range(min(map(len, responses)))
        if len({value[index] for value in responses}) == 1
    )
    counts = [0] * 256
    for response in responses:
        for octet in response:
            counts[octet] += 1
    return Comparison(
        summaries=summaries,
        exact_match=len(set(responses)) == 1,
        common_prefix=_common_prefix(responses),
        common_suffix=_common_suffix(responses),
        common_positions=common_positions,
        byte_frequency=tuple((value, count) for value, count in enumerate(counts) if count),
    )
