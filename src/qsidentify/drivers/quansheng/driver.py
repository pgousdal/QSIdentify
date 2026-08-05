from __future__ import annotations

from collections.abc import Mapping

from qsidentify.drivers.base import (
    CatalogValidation,
    Driver,
    DriverInfo,
    FirmwareProjectInfo,
    HardwareInfo,
)
from qsidentify.models import Capture, Command, DecodedResponse, StreamAnalysis

from .advisory import FirmwareAdvisory, HardwareInput, build_advisory
from .catalog import load_firmware_catalog, load_hardware_records, validate_catalogs
from .commands import ALLOWLIST, IDENTIFY_HANDSHAKE
from .decoder import decode_response
from .frame import encode_frame
from .stream import analyze_stream


class QuanshengDriver(Driver):
    @property
    def info(self) -> DriverInfo:
        return DriverInfo(
            id="quansheng",
            version="1.0",
            name="Quansheng built-in driver",
            protocols=("Quansheng framed protocol",),
            models=("UV-K5", "UV-K5(8)", "UV-K6", "UV-5R Plus"),
            vid_pid=(),
        )

    def supported_commands(self) -> tuple[Command, ...]:
        return ALLOWLIST

    def identify(self) -> Command:
        return IDENTIFY_HANDSHAKE

    def encode(self, command: Command) -> bytes:
        if command not in ALLOWLIST:
            raise ValueError("Refusing to encode a command outside the driver allowlist.")
        return encode_frame(command.payload)

    def analyze_stream(self, raw_response: bytes, transmitted_frame: bytes) -> StreamAnalysis:
        return analyze_stream(raw_response, transmitted_frame)

    def decode(self, frame: bytes, *, incomplete: bool = False) -> DecodedResponse:
        return decode_response(frame, incomplete=incomplete)

    def firmware_advice(
        self,
        capture: Capture,
        hardware_input: Mapping[str, str | None] | None = None,
    ) -> FirmwareAdvisory:
        value = HardwareInput(**hardware_input) if hardware_input is not None else HardwareInput()
        return build_advisory(capture, value)

    def firmware_projects(self) -> tuple[FirmwareProjectInfo, ...]:
        return tuple(
            FirmwareProjectInfo(entry.id, entry.supported_mcus, entry.status, entry.project)
            for entry in load_firmware_catalog().entries
        )

    def hardware_records(self) -> tuple[HardwareInfo, ...]:
        return tuple(
            HardwareInfo(record.id, record.revision, record.mcu, record.evidence_requirements)
            for record in load_hardware_records()
        )

    def validate_catalog(self) -> CatalogValidation:
        records, catalog = validate_catalogs()
        return CatalogValidation(catalog.catalog_version, len(catalog.entries), len(records))


__all__ = ["QuanshengDriver"]
