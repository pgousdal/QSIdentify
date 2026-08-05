from .base import CatalogValidation, Driver, DriverInfo, FirmwareProjectInfo, HardwareInfo
from .quansheng import QuanshengDriver
from .registry import DriverRegistry

BUILTIN_DRIVERS = DriverRegistry((QuanshengDriver(),), default_id="quansheng")


def drivers() -> tuple[Driver, ...]:
    return BUILTIN_DRIVERS.drivers()


def default_driver() -> Driver:
    return BUILTIN_DRIVERS.default_driver()


def get_driver(driver_id: str) -> Driver:
    return BUILTIN_DRIVERS.get(driver_id)


__all__ = [
    "BUILTIN_DRIVERS",
    "CatalogValidation",
    "Driver",
    "DriverInfo",
    "DriverRegistry",
    "FirmwareProjectInfo",
    "HardwareInfo",
    "default_driver",
    "drivers",
    "get_driver",
]
