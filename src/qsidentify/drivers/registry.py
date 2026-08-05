from __future__ import annotations

from qsidentify.drivers.base import Driver


class DriverRegistry:
    def __init__(self, drivers: tuple[Driver, ...] = (), *, default_id: str | None = None) -> None:
        self._drivers: dict[str, Driver] = {}
        self._default_id = default_id
        for driver in drivers:
            self.register(driver)

    def register(self, driver: Driver) -> None:
        if driver.info.id in self._drivers:
            raise ValueError(f"Driver '{driver.info.id}' is already registered.")
        self._drivers[driver.info.id] = driver

    def drivers(self) -> tuple[Driver, ...]:
        return tuple(self._drivers[key] for key in sorted(self._drivers))

    def get(self, driver_id: str) -> Driver:
        try:
            return self._drivers[driver_id]
        except KeyError as exc:
            raise KeyError(f"Unknown driver '{driver_id}'.") from exc

    def find_by_model(self, model: str) -> tuple[Driver, ...]:
        normalized = model.casefold()
        return tuple(
            driver
            for driver in self.drivers()
            if any(candidate.casefold() == normalized for candidate in driver.supported_models())
        )

    def find_by_protocol(self, protocol: str) -> tuple[Driver, ...]:
        normalized = protocol.casefold()
        return tuple(
            driver
            for driver in self.drivers()
            if any(candidate.casefold() == normalized for candidate in driver.supported_protocols())
        )

    def find_by_vid_pid(self, vid: int, pid: int) -> tuple[Driver, ...]:
        return tuple(
            driver for driver in self.drivers() if (vid, pid) in driver.supported_vid_pid()
        )

    def default_driver(self) -> Driver:
        drivers = self.drivers()
        if not drivers:
            raise RuntimeError("No radio drivers are registered.")
        if self._default_id is not None:
            return self.get(self._default_id)
        return drivers[0]


__all__ = ["DriverRegistry"]
