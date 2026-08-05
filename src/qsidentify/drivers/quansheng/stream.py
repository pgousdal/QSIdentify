from __future__ import annotations

from qsidentify.models import FrameCandidate, StreamAnalysis, TransportClassification

from .frame import (
    FRAME_HEADER,
    HEADER_SIZE,
    FrameError,
    decode_frame,
    frame_size_from_header,
)


def _partial_echo_suffix(data: bytes, transmitted_frame: bytes) -> bytes | None:
    if not data or not transmitted_frame:
        return None
    maximum = min(len(data), len(transmitted_frame) - 1)
    for size in range(maximum, 0, -1):
        if data[-size:] == transmitted_frame[:size]:
            return data[-size:]
    return None


def analyze_stream(raw_response: bytes, transmitted_frame: bytes = b"") -> StreamAnalysis:
    candidates: list[FrameCandidate] = []
    echoes: list[bytes] = []
    valid_frames = []
    consumed: list[tuple[int, int]] = []
    cursor = 0
    first_candidate_offset: int | None = None

    while cursor < len(raw_response):
        offset = raw_response.find(FRAME_HEADER, cursor)
        if offset < 0:
            break
        if first_candidate_offset is None:
            first_candidate_offset = offset
        if len(raw_response) - offset < HEADER_SIZE:
            data = raw_response[offset:]
            candidates.append(FrameCandidate(offset, data, False, False, "incomplete header"))
            cursor = len(raw_response)
            break
        try:
            size = frame_size_from_header(raw_response[offset : offset + HEADER_SIZE])
        except FrameError as exc:
            data = raw_response[offset : offset + HEADER_SIZE]
            candidates.append(FrameCandidate(offset, data, False, False, str(exc)))
            cursor = offset + 1
            continue
        end = offset + size
        if end > len(raw_response):
            data = raw_response[offset:]
            candidates.append(FrameCandidate(offset, data, False, False, "incomplete frame"))
            cursor = len(raw_response)
            break
        data = raw_response[offset:end]
        echo = bool(transmitted_frame) and data == transmitted_frame
        if echo:
            echoes.append(data)
            candidates.append(FrameCandidate(offset, data, True, True))
            consumed.append((offset, end))
            cursor = end
            continue
        try:
            decoded = decode_frame(data)
        except FrameError as exc:
            candidates.append(FrameCandidate(offset, data, False, False, str(exc)))
            cursor = offset + 1
            continue
        candidates.append(FrameCandidate(offset, data, True, False, decoded=decoded))
        valid_frames.append(decoded)
        consumed.append((offset, end))
        cursor = end

    unparsed = bytearray()
    position = 0
    for start, end in consumed:
        if start > position:
            unparsed.extend(raw_response[position:start])
        position = max(position, end)
    unparsed.extend(raw_response[position:])
    leading = (
        raw_response[: first_candidate_offset or 0]
        if first_candidate_offset is not None
        else raw_response
    )
    trailing = raw_response[consumed[-1][1] :] if consumed else raw_response
    partial_echo = _partial_echo_suffix(bytes(unparsed), transmitted_frame)

    if not raw_response:
        classification = TransportClassification.NO_RESPONSE
    elif valid_frames and echoes:
        classification = TransportClassification.ECHO_FOLLOWED_BY_RESPONSE
    elif valid_frames:
        classification = TransportClassification.FRAMED_RESPONSE
    elif echoes and not unparsed:
        classification = TransportClassification.ECHO_ONLY
    elif echoes:
        classification = TransportClassification.TRANSMIT_ECHO
    elif partial_echo is not None:
        classification = TransportClassification.PARTIAL_TRANSMIT_ECHO
    elif all(octet == 0 for octet in raw_response):
        classification = TransportClassification.NULL_BYTE_RESPONSE
    elif any(item.error and item.error.startswith("incomplete") for item in candidates):
        classification = TransportClassification.INCOMPLETE_RESPONSE
    elif any(not item.valid for item in candidates):
        classification = TransportClassification.INVALID_FRAME
    else:
        classification = TransportClassification.UNFRAMED_BINARY_RESPONSE

    return StreamAnalysis(
        raw_response=raw_response,
        classification=classification,
        leading_bytes=leading,
        echo_frames=tuple(echoes),
        candidates=tuple(candidates),
        valid_response_frames=tuple(valid_frames),
        unparsed_bytes=bytes(unparsed),
        trailing_bytes=trailing,
        partial_echo=partial_echo,
    )


__all__ = ["analyze_stream"]
