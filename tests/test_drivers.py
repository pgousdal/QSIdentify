from pathlib import Path

import pytest

from qsidentify.drivers import default_driver, drivers, get_driver
from qsidentify.drivers.quansheng import QuanshengDriver
from qsidentify.drivers.registry import DriverRegistry
from qsidentify.models import SafetyClass


def test_builtin_registry_is_deterministic() -> None:
    assert [driver.info.id for driver in drivers()] == ["quansheng"]
    assert default_driver() is get_driver("quansheng")
    assert get_driver("quansheng").info.version == "1.0"


def test_registry_selection_and_duplicate_rejection() -> None:
    driver = QuanshengDriver()
    registry = DriverRegistry((driver,))
    assert registry.find_by_model("uv-k5(8)") == (driver,)
    assert registry.find_by_protocol("quansheng framed protocol") == (driver,)
    assert registry.find_by_vid_pid(0x1A86, 0x7523) == ()
    with pytest.raises(ValueError):
        registry.register(QuanshengDriver())


def test_quansheng_driver_is_read_only_and_round_trips_command() -> None:
    driver = QuanshengDriver()
    command = driver.identify()
    assert command.safety is SafetyClass.READ_ONLY
    frame = driver.encode(command)
    assert driver.decode(frame).frame is not None
    assert driver.analyze_stream(frame, frame).classification.value == "echo-only"


def test_transport_has_no_quansheng_protocol_knowledge() -> None:
    source = Path("src/qsidentify/transport.py").read_text().casefold()
    assert "quansheng" not in source
    assert ".protocol" not in source


def test_driver_implementation_has_no_serial_io() -> None:
    sources = "\n".join(
        path.read_text().casefold()
        for path in Path("src/qsidentify/drivers/quansheng").rglob("*.py")
    )
    assert "import serial" not in sources
    assert "serial.serial" not in sources
