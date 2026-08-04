from __future__ import annotations

import serial

from .models import Exchange


def exchange(
    device: str,
    request: bytes,
    *,
    baud_rate: int = 38400,
    timeout: float = 1.0,
    max_response: int = 512,
) -> Exchange:
    if max_response <= 0:
        raise ValueError("max_response must be positive")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    with serial.Serial(
        port=device,
        baudrate=baud_rate,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=timeout,
        write_timeout=timeout,
    ) as connection:
        connection.reset_input_buffer()
        connection.write(request)
        connection.flush()
        response = connection.read(max_response)

    return Exchange(request=request, response=response)
