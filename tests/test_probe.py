from qsidentify.models import MessageType, PortInfo, TransportClassification
from qsidentify.probe import probe_port
from qsidentify.protocol.commands import IDENTIFY_HANDSHAKE
from qsidentify.protocol.frame import encode_frame


class ProbeSerial:
    def __init__(self, response: bytes) -> None:
        self.response = bytearray(response)
        self.dtr = True
        self.rts = True

    def reset_input_buffer(self) -> None:
        pass

    def reset_output_buffer(self) -> None:
        pass

    def write(self, data: bytes) -> int:
        return len(data)

    def flush(self) -> None:
        pass

    def read(self, size: int = 1) -> bytes:
        chunk = bytes(self.response[:size])
        del self.response[:size]
        return chunk

    def close(self) -> None:
        pass


def serial_factory(response: bytes):
    def create(**_kwargs: object) -> ProbeSerial:
        return ProbeSerial(response)

    return create


def run_probe(response: bytes):  # type: ignore[no-untyped-def]
    return probe_port(
        PortInfo("test"),
        timeout=0.01,
        idle_timeout=0.005,
        settle_delay=0,
        serial_factory=serial_factory(response),
    )


def test_probe_no_response() -> None:
    result = run_probe(b"")
    assert result.report.message_type is MessageType.NO_RESPONSE
    assert not result.report.response_received


def test_echo_is_not_a_radio_response() -> None:
    result = run_probe(IDENTIFY_HANDSHAKE.encoded_frame())
    assert result.report.message_type is MessageType.ECHO_ONLY
    assert result.report.operating_mode == "unknown"
    assert result.report.detected_protocol == "Serial transmit echo"
    assert result.report.transport_classification is TransportClassification.ECHO_ONLY


def test_null_and_mixed_binary_are_not_protocols() -> None:
    nulls = run_probe(b"\x00\x00\x00")
    assert nulls.report.message_type is MessageType.NULL_BYTE_RESPONSE
    mixed = run_probe(b"\x00\x20\x02\x29")
    assert mixed.report.message_type is MessageType.UNFRAMED_BINARY_RESPONSE


def test_probe_uses_valid_response_after_echo() -> None:
    response = encode_frame(b"\x15\x05V1.0\x00")
    result = run_probe(IDENTIFY_HANDSHAKE.encoded_frame() + response)
    assert (
        result.report.transport_classification
        is TransportClassification.ECHO_FOLLOWED_BY_RESPONSE
    )
    assert result.report.message_type is MessageType.FIRMWARE_IDENTIFICATION
    assert result.report.reported_version == "V1.0"
