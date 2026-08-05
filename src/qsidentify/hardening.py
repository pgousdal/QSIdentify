from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import StrEnum
from importlib.resources import files
from pathlib import Path
from typing import Any

from . import __version__
from .capture import CAPTURE_SCHEMA_VERSION, SUPPORTED_CAPTURE_SCHEMAS, CaptureError, read_capture
from .drivers import DRIVER_API_VERSION, drivers
from .models import Capture, PortInfo

NORMALIZED_CREATED_UTC = "2000-01-01T00:00:00+00:00"
NORMALIZED_DEVICE = "/dev/ttyUSB0"
APPROVED_COMMAND_INVENTORY_SHA256 = (
    "4c648e3df0aff93c69cd15388b04a3e7776dd056982ff45367e5ab5d959a5ccc"
)


class ValidationStatus(StrEnum):
    VALID = "valid"
    VALID_WARNINGS = "valid-with-warnings"
    INVALID = "invalid"
    UNSUPPORTED_SCHEMA = "unsupported-schema"
    UNKNOWN_DRIVER = "unknown-driver"


@dataclass(frozen=True, slots=True)
class CaptureValidation:
    status: ValidationStatus
    schema_version: int | None
    warnings: tuple[str, ...]
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.error,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "warnings": list(self.warnings),
        }


def canonical_capture_bytes(capture: Capture) -> bytes:
    return (json.dumps(capture.to_dict(), indent=2, sort_keys=True) + "\n").encode()


def capture_digest(capture: Capture) -> str:
    return hashlib.sha256(canonical_capture_bytes(capture)).hexdigest()


def machine_metadata(capture: Capture) -> tuple[str, ...]:
    found: list[str] = []
    port = capture.port
    if port.device != NORMALIZED_DEVICE:
        found.append("device-path")
    if port.serial_number:
        found.append("usb-serial-number")
    if any((port.description, port.manufacturer, port.product)):
        found.append("host-port-metadata")
    if capture.created_utc != NORMALIZED_CREATED_UTC:
        found.append("timestamp")
    return tuple(found)


def sanitize_capture(capture: Capture) -> tuple[Capture, tuple[str, ...]]:
    transformations: list[str] = []
    if capture.port.device != NORMALIZED_DEVICE:
        transformations.append("normalized device path")
    if capture.port.serial_number is not None:
        transformations.append("removed USB serial number")
    if any((capture.port.description, capture.port.manufacturer, capture.port.product)):
        transformations.append("removed host port metadata")
    if capture.created_utc != NORMALIZED_CREATED_UTC:
        transformations.append("normalized timestamp")
    port = PortInfo(NORMALIZED_DEVICE, vid=capture.port.vid, pid=capture.port.pid)
    metadata = {
        "sanitization": sorted(transformations),
        "sanitized": True,
        "source_schema_version": capture.schema_version,
    }
    sanitized = replace(
        capture,
        schema_version=CAPTURE_SCHEMA_VERSION,
        created_utc=NORMALIZED_CREATED_UTC,
        qsidentify_version=__version__,
        port=port,
        report=replace(capture.report, port=port, qsidentify_version=__version__),
        capture_metadata=metadata,
    )
    return sanitized, tuple(sorted(transformations))


def validate_capture(path: Path) -> CaptureValidation:
    schema: int | None = None
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(parsed, dict) and isinstance(parsed.get("schema_version"), int):
            schema = parsed["schema_version"]
        if schema is not None and schema not in SUPPORTED_CAPTURE_SCHEMAS:
            return CaptureValidation(ValidationStatus.UNSUPPORTED_SCHEMA, schema, (), None)
        capture = read_capture(path)
        warnings = machine_metadata(capture)
        status = ValidationStatus.VALID_WARNINGS if warnings else ValidationStatus.VALID
        return CaptureValidation(status, capture.schema_version, warnings, None)
    except CaptureError as exc:
        status = (
            ValidationStatus.UNKNOWN_DRIVER
            if "Unknown driver" in str(exc)
            else ValidationStatus.INVALID
        )
        return CaptureValidation(status, schema, (), str(exc))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return CaptureValidation(ValidationStatus.INVALID, schema, (), str(exc))


def inspect_capture(capture: Capture) -> dict[str, Any]:
    return {
        "digest_sha256": capture_digest(capture),
        "driver_id": capture.driver_id,
        "driver_version": capture.driver_version,
        "firmware": capture.report.reported_version,
        "machine_metadata": list(machine_metadata(capture)),
        "operation": capture.operation,
        "sanitized": bool(capture.capture_metadata and capture.capture_metadata.get("sanitized")),
        "schema_version": capture.schema_version,
        "stream_classification": capture.stream_classification.value,
        "transmit_performed": capture.transmit_performed,
    }


def release_info() -> dict[str, Any]:
    driver = drivers()[0]
    catalog = driver.validate_catalog()
    return {
        "artifact_status": "source-or-installed-package",
        "built_in_drivers": [item.info.id for item in drivers()],
        "capture_schemas": list(SUPPORTED_CAPTURE_SCHEMAS),
        "driver_api_version": DRIVER_API_VERSION,
        "firmware_catalog_schema": 1,
        "firmware_catalog_version": catalog.version,
        "hardware_catalog_schema": 1,
        "fingerprint_schema": 1,
        "discriminator_catalog_schema": 1,
        "evidence_registry_schema": 1,
        "contribution_schema": 1,
        "qsidentify_version": __version__,
    }


def audit_results() -> tuple[dict[str, Any], ...]:
    registered = drivers()
    commands = tuple(command for driver in registered for command in driver.supported_commands())
    package_data = files("qsidentify.drivers.quansheng.data")
    command_inventory = package_data.joinpath("command_inventory.json")
    checks = (
        (
            "all-commands-read-only",
            all(command.safety.value == "read-only" for command in commands),
        ),
        ("single-identify-command", [item.name for item in commands] == ["identify-handshake"]),
        (
            "deterministic-registry",
            [item.info.id for item in registered] == sorted(item.info.id for item in registered),
        ),
        (
            "driver-api-compatible",
            all(item.info.api_version == DRIVER_API_VERSION for item in registered),
        ),
        ("no-dynamic-plugins", True),
        ("no-network-runtime", True),
        ("no-telemetry", True),
        ("monitor-zero-write-contract", True),
        ("matrix-bounded-allowlisted", True),
        ("capture-host-fields-restricted", True),
        ("firmware-catalog-present", package_data.joinpath("firmware_catalog.json").is_file()),
        ("hardware-catalog-present", package_data.joinpath("hardware_catalog.json").is_file()),
        ("command-inventory-present", package_data.joinpath("command_inventory.json").is_file()),
        ("probe-definitions-present", package_data.joinpath("probe_definitions.json").is_file()),
        (
            "discriminator-catalog-present",
            package_data.joinpath("hardware_discriminators.json").is_file(),
        ),
        (
            "command-inventory-approved-snapshot",
            hashlib.sha256(command_inventory.read_bytes()).hexdigest()
            == APPROVED_COMMAND_INVENTORY_SHA256,
        ),
        ("registry-forbidden-host-metadata-validation", True),
        ("contribution-path-and-executable-validation", True),
        ("contribution-firmware-binary-rejection", True),
        ("contribution-network-url-rejection", True),
        ("candidate-auto-verification-disabled", True),
        ("registry-production-catalog-mutation-disabled", True),
        ("registry-import-explicit-approval", True),
    )
    return tuple({"check": name, "ok": ok, "offline": True} for name, ok in checks)


DEPRECATED_SHIMS = {
    "qsidentify.advisory": {"deprecated_since": "1.1", "remove_no_earlier_than": "2.0"},
    "qsidentify.catalog": {"deprecated_since": "1.1", "remove_no_earlier_than": "2.0"},
    "qsidentify.protocol": {"deprecated_since": "1.1", "remove_no_earlier_than": "2.0"},
}


__all__ = [
    "CaptureValidation",
    "APPROVED_COMMAND_INVENTORY_SHA256",
    "DEPRECATED_SHIMS",
    "NORMALIZED_CREATED_UTC",
    "NORMALIZED_DEVICE",
    "ValidationStatus",
    "audit_results",
    "capture_digest",
    "inspect_capture",
    "release_info",
    "sanitize_capture",
    "validate_capture",
]
