from qsidentify.models import MessageType, PortInfo
from qsidentify.probe import probe_port
from qsidentify.protocol.frame import encode_frame
from qsidentify.transport import SerialConnection


class ProbeSerial:
    def __init__(self, response: bytes) -> None:
        self.response = bytearray(response)

    def reset_input_buffer(self) -> None:
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
    def create(**_kwargs: object) -> SerialConnection:
        return ProbeSerial(response)

    return create


def test_probe_converts_no_response_to_diagnostic_result() -> None:
    result = probe_port(
        PortInfo("test"), timeout=0.001, serial_factory=serial_factory(b"")
    )
    assert result.report.message_type is MessageType.NO_RESPONSE
    assert not result.exchange.complete
    assert not result.report.response_received


def test_probe_converts_partial_frame_to_diagnostic_result() -> None:
    partial = encode_frame(b"reply")[:-2]
    result = probe_port(
        PortInfo("test"), timeout=0.002, serial_factory=serial_factory(partial)
    )
    assert result.report.message_type is MessageType.INCOMPLETE_RESPONSE
    assert result.report.frame_detected
    assert not result.report.frame_complete
    assert result.exchange.received_frame == partial
    assert result.exchange.expected_frame_size == len(partial) + 2
