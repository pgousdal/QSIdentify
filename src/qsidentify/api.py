from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .drivers import DriverInfo, get_driver
from .models import LineSetting, ProbeReport
from .ports import find_port
from .probe import probe_port


@dataclass(frozen=True, slots=True)
class IdentificationResult:
    driver: DriverInfo
    report: ProbeReport

    def to_dict(self) -> dict[str, Any]:
        return {
            "driver": self.driver.id,
            "driver_version": self.driver.version,
            **self.report.to_dict(),
        }


def identify(
    device: str,
    *,
    driver_id: str = "quansheng",
    baud_rate: int = 38400,
    timeout: float = 3.0,
    idle_timeout: float = 0.2,
    settle_delay: float = 0.1,
    dtr: LineSetting = LineSetting.AUTO,
    rts: LineSetting = LineSetting.AUTO,
) -> IdentificationResult:
    """Identify a radio using a compiled-in read-only driver."""
    driver = get_driver(driver_id)
    result = probe_port(
        find_port(device),
        driver=driver,
        baud_rate=baud_rate,
        timeout=timeout,
        idle_timeout=idle_timeout,
        settle_delay=settle_delay,
        dtr=dtr,
        rts=rts,
    )
    return IdentificationResult(driver.info, result.report)


__all__ = ["IdentificationResult", "identify"]
