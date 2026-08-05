from __future__ import annotations

from serial.tools import list_ports

from .models import PortInfo


def list_serial_ports() -> tuple[PortInfo, ...]:
    ports: list[PortInfo] = []
    for port in list_ports.comports():
        ports.append(
            PortInfo(
                device=port.device,
                description=port.description or None,
                manufacturer=port.manufacturer or None,
                product=port.product or None,
                serial_number=port.serial_number or None,
                vid=port.vid,
                pid=port.pid,
            )
        )
    return tuple(sorted(ports, key=lambda item: item.device))


def find_port(device: str) -> PortInfo:
    for port in list_serial_ports():
        if port.device == device:
            return port
    return PortInfo(device=device)


def choose_auto_port() -> PortInfo:
    ports = list_serial_ports()
    if not ports:
        raise RuntimeError("No serial ports were found.")

    preferred = [
        port
        for port in ports
        if port.vid_pid in {"1a86:7523", "1a86:5523"}
        or "ch340" in (port.description or "").lower()
        or "usb serial" in (port.description or "").lower()
    ]
    if len(preferred) == 1:
        return preferred[0]
    if len(ports) == 1:
        return ports[0]
    raise RuntimeError("Multiple candidate serial ports were found. Specify the port explicitly.")
