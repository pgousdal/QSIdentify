from __future__ import annotations

from qsidentify.models import ChecksumStatus, DecodedFrame

FRAME_HEADER = bytes.fromhex("ab cd")
FRAME_FOOTER = bytes.fromhex("dc ba")
XOR_KEY = bytes.fromhex("16 6c 14 e6 2e 91 0d 40 21 35 d5 40 13 03 e9 80")
LENGTH_SIZE = 1
RESERVED_SIZE = 1
RESERVED_VALUE = 0
HEADER_SIZE = len(FRAME_HEADER) + LENGTH_SIZE + RESERVED_SIZE
CHECKSUM_SIZE = 2
FOOTER_SIZE = 2
MAX_PAYLOAD_SIZE = 0xFF
MIN_FRAME_SIZE = HEADER_SIZE + CHECKSUM_SIZE + FOOTER_SIZE


class FrameError(ValueError):
    """Base class for invalid Quansheng frames."""


class InvalidHeaderError(FrameError):
    pass


class InvalidFooterError(FrameError):
    pass


class TruncatedFrameError(FrameError):
    pass


class InvalidLengthError(FrameError):
    pass


class InvalidReservedByteError(FrameError):
    pass


class ChecksumMismatchError(FrameError):
    pass


def _crc16_1021(data: bytes, initial: int) -> int:
    crc = initial
    for octet in data:
        crc ^= octet << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def crc16_xmodem(data: bytes) -> int:
    """Return standard CRC-16/XMODEM (poly 0x1021, initial value 0)."""
    return _crc16_1021(data, 0)


def xor_transform(data: bytes) -> bytes:
    return bytes(octet ^ XOR_KEY[index % len(XOR_KEY)] for index, octet in enumerate(data))


def frame_size_from_header(header: bytes, *, max_payload_size: int = MAX_PAYLOAD_SIZE) -> int:
    if len(header) < HEADER_SIZE:
        raise TruncatedFrameError("Frame header is incomplete.")
    if header[:2] != FRAME_HEADER:
        raise InvalidHeaderError("Invalid frame header.")
    if header[3] != RESERVED_VALUE:
        raise InvalidReservedByteError(f"Reserved header byte must be 00, got {header[3]:02x}.")
    payload_length = header[2]
    if payload_length > max_payload_size:
        raise InvalidLengthError(
            f"Declared payload length {payload_length} exceeds limit {max_payload_size}."
        )
    return HEADER_SIZE + payload_length + CHECKSUM_SIZE + FOOTER_SIZE


def encode_frame(payload: bytes) -> bytes:
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise InvalidLengthError(f"Payload exceeds maximum length {MAX_PAYLOAD_SIZE}.")
    checksum = crc16_xmodem(payload).to_bytes(2, "little")
    protected = xor_transform(payload + checksum)
    return FRAME_HEADER + bytes((len(payload), RESERVED_VALUE)) + protected + FRAME_FOOTER


def decode_frame(frame: bytes, *, accept_legacy_checksum: bool = True) -> DecodedFrame:
    if not frame:
        raise TruncatedFrameError("Frame is empty.")
    if len(frame) < HEADER_SIZE:
        if FRAME_HEADER.startswith(frame):
            raise TruncatedFrameError("Frame header is incomplete.")
        raise InvalidHeaderError("Invalid frame header.")
    expected_size = frame_size_from_header(frame[:HEADER_SIZE])
    if len(frame) < expected_size:
        raise TruncatedFrameError(
            f"Frame is truncated: expected {expected_size}, got {len(frame)}."
        )
    if len(frame) > expected_size:
        raise InvalidLengthError(
            f"Frame has trailing bytes: expected {expected_size}, got {len(frame)}."
        )
    if frame[-FOOTER_SIZE:] != FRAME_FOOTER:
        raise InvalidFooterError("Invalid frame footer.")

    payload_length = frame[2]
    protected = xor_transform(frame[HEADER_SIZE:-FOOTER_SIZE])
    payload = protected[:payload_length]
    checksum_bytes = protected[payload_length:]
    checksum_calculated = crc16_xmodem(payload)
    if checksum_bytes == b"\xff\xff" and accept_legacy_checksum:
        status = ChecksumStatus.LEGACY_FF_FF
        checksum_received = None
    else:
        checksum_received = int.from_bytes(checksum_bytes, "little")
        status = (
            ChecksumStatus.VALID
            if checksum_received == checksum_calculated
            else ChecksumStatus.INVALID
        )
        if status is ChecksumStatus.INVALID:
            raise ChecksumMismatchError(
                f"Checksum mismatch: received {checksum_received:04x}, "
                f"calculated {checksum_calculated:04x}."
            )
    return DecodedFrame(
        original=frame,
        payload=payload,
        checksum_received=checksum_received,
        checksum_calculated=checksum_calculated,
        checksum_status=status,
    )
