from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from qsidentify.models import Capture, Command, DecodedResponse, StreamAnalysis


@dataclass(frozen=True, slots=True)
class DriverInfo:
    id: str
    version: str
    name: str
    protocols: tuple[str, ...]
    models: tuple[str, ...]
    vid_pid: tuple[tuple[int, int], ...]
    safety: str = "read-only"


@dataclass(frozen=True, slots=True)
class FirmwareProjectInfo:
    id: str
    supported_mcus: tuple[str, ...]
    status: str
    project: str


@dataclass(frozen=True, slots=True)
class HardwareInfo:
    id: str
    revision: str
    mcu: str
    evidence_requirements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CatalogValidation:
    version: str
    firmware_entries: int
    hardware_records: int


class Driver(ABC):
    """Pure protocol interpreter; drivers must never perform serial I/O."""

    @property
    @abstractmethod
    def info(self) -> DriverInfo: ...

    def supported_models(self) -> tuple[str, ...]:
        return self.info.models

    def supported_vid_pid(self) -> tuple[tuple[int, int], ...]:
        return self.info.vid_pid

    def supported_protocols(self) -> tuple[str, ...]:
        return self.info.protocols

    @abstractmethod
    def supported_commands(self) -> tuple[Command, ...]: ...

    @abstractmethod
    def identify(self) -> Command: ...

    @abstractmethod
    def encode(self, command: Command) -> bytes: ...

    @abstractmethod
    def analyze_stream(self, raw_response: bytes, transmitted_frame: bytes) -> StreamAnalysis: ...

    @abstractmethod
    def decode(self, frame: bytes, *, incomplete: bool = False) -> DecodedResponse: ...

    def classify(self, raw_response: bytes, transmitted_frame: bytes) -> StreamAnalysis:
        return self.analyze_stream(raw_response, transmitted_frame)

    def firmware_advice(
        self,
        capture: Capture,
        hardware_input: Mapping[str, str | None] | None = None,
    ) -> Any:
        raise NotImplementedError(f"Driver '{self.info.id}' has no firmware advisory.")

    def firmware_projects(self) -> tuple[FirmwareProjectInfo, ...]:
        return ()

    def hardware_records(self) -> tuple[HardwareInfo, ...]:
        return ()

    def validate_catalog(self) -> CatalogValidation:
        raise NotImplementedError(f"Driver '{self.info.id}' has no firmware catalog.")


__all__ = [
    "CatalogValidation",
    "Driver",
    "DriverInfo",
    "FirmwareProjectInfo",
    "HardwareInfo",
]
