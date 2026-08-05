from .commands import IDENTIFY_HANDSHAKE
from .decoder import decode_response
from .frame import crc16_xmodem, decode_frame, encode_frame, xor_transform
from .stream import analyze_stream

__deprecated_since__ = "1.1"
__remove_no_earlier_than__ = "2.0"

__all__ = [
    "IDENTIFY_HANDSHAKE",
    "crc16_xmodem",
    "decode_frame",
    "decode_response",
    "encode_frame",
    "xor_transform",
    "analyze_stream",
]
