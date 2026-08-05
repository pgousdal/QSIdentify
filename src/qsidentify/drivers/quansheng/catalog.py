from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, NoReturn

KNOWN_MCUS = frozenset({"DP32G030", "PY32F030", "PY32F071"})
KNOWN_PROJECT_STATUSES = frozenset({"known-project"})
KNOWN_RISKS = frozenset({"high"})
CATALOG_SCHEMA_VERSION = 1


class CatalogError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class HardwareRecord:
    id: str
    manufacturer: str
    marketed_models: tuple[str, ...]
    revision: str
    pcb_markings: tuple[str, ...]
    mcu: str
    known_bootloaders: tuple[str, ...]
    identification_notes: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    source_references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CatalogSource:
    source_type: str
    project: str
    reference: str
    observed_at: str
    notes: str


@dataclass(frozen=True, slots=True)
class FirmwareEntry:
    id: str
    name: str
    project: str
    status: str
    supported_mcus: tuple[str, ...]
    supported_revisions: tuple[str, ...]
    unsupported_revisions: tuple[str, ...]
    requires_matching_chirp_driver: bool
    risk: str
    notes: tuple[str, ...]
    sources: tuple[CatalogSource, ...]


@dataclass(frozen=True, slots=True)
class FirmwareCatalog:
    schema_version: int
    catalog_version: str
    generated_at: str | None
    entries: tuple[FirmwareEntry, ...]


def _fail(message: str) -> NoReturn:
    raise CatalogError(message)


def _object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"Catalog field '{field}' must be an object.")
    return value


def _string(raw: dict[str, Any], field: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value.strip():
        _fail(f"Catalog field '{field}' must be a non-empty string.")
    return value


def _strings(raw: dict[str, Any], field: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    value = raw.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        _fail(f"Catalog field '{field}' must be a list of non-empty strings.")
    if not allow_empty and not value:
        _fail(f"Catalog field '{field}' must not be empty.")
    if len(value) != len(set(value)):
        _fail(f"Catalog field '{field}' contains duplicates.")
    return tuple(value)


def _read_json(path: Path | None, resource: str) -> dict[str, Any]:
    try:
        text = (
            path.read_text(encoding="utf-8")
            if path
            else files("qsidentify.drivers.quansheng.data")
            .joinpath(resource)
            .read_text(encoding="utf-8")
        )
        parsed = json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CatalogError(f"Could not read catalog: {exc}") from exc
    return _object(parsed, "root")


def load_hardware_records(path: Path | None = None) -> tuple[HardwareRecord, ...]:
    raw = _read_json(path, "hardware_catalog.json")
    if raw.get("schema_version") != CATALOG_SCHEMA_VERSION:
        _fail("Unsupported hardware catalog schema version.")
    values = raw.get("records")
    if not isinstance(values, list):
        _fail("Hardware catalog records must be a list.")
    records: list[HardwareRecord] = []
    for index, item in enumerate(values):
        value = _object(item, f"records[{index}]")
        mcu = _string(value, "mcu").upper()
        if mcu not in KNOWN_MCUS:
            _fail(f"Unknown MCU identifier '{mcu}'.")
        records.append(
            HardwareRecord(
                id=_string(value, "id"),
                manufacturer=_string(value, "manufacturer"),
                marketed_models=_strings(value, "marketed_models", allow_empty=False),
                revision=_string(value, "revision"),
                pcb_markings=_strings(value, "pcb_markings", allow_empty=False),
                mcu=mcu,
                known_bootloaders=_strings(value, "known_bootloaders"),
                identification_notes=_strings(value, "identification_notes", allow_empty=False),
                evidence_requirements=_strings(value, "evidence_requirements", allow_empty=False),
                source_references=_strings(value, "source_references", allow_empty=False),
            )
        )
    ids = [item.id for item in records]
    if len(ids) != len(set(ids)):
        _fail("Hardware record IDs must be unique.")
    return tuple(sorted(records, key=lambda item: item.id))


def _source(raw: dict[str, Any]) -> CatalogSource:
    return CatalogSource(
        source_type=_string(raw, "source_type"),
        project=_string(raw, "project"),
        reference=_string(raw, "reference"),
        observed_at=_string(raw, "observed_at"),
        notes=_string(raw, "notes"),
    )


def load_firmware_catalog(path: Path | None = None) -> FirmwareCatalog:
    raw = _read_json(path, "firmware_catalog.json")
    if raw.get("schema_version") != CATALOG_SCHEMA_VERSION:
        _fail("Unsupported firmware catalog schema version.")
    version = _string(raw, "catalog_version")
    generated_at = raw.get("generated_at")
    if generated_at is not None and not isinstance(generated_at, str):
        _fail("Catalog generated_at must be a string or null.")
    values = raw.get("entries")
    if not isinstance(values, list):
        _fail("Firmware catalog entries must be a list.")
    hardware = load_hardware_records()
    revision_ids = {item.id for item in hardware}
    entries: list[FirmwareEntry] = []
    for index, item in enumerate(values):
        value = _object(item, f"entries[{index}]")
        mcus = tuple(item.upper() for item in _strings(value, "supported_mcus", allow_empty=False))
        if not set(mcus) <= KNOWN_MCUS:
            _fail("Firmware entry contains an unknown MCU identifier.")
        supported = _strings(value, "supported_revisions", allow_empty=False)
        unsupported = _strings(value, "unsupported_revisions")
        if not set(supported + unsupported) <= revision_ids:
            _fail("Firmware entry contains an unknown hardware revision ID.")
        if set(supported) & set(unsupported):
            _fail("Firmware entry supports and rejects the same hardware revision.")
        sources_raw = value.get("sources")
        if not isinstance(sources_raw, list) or not sources_raw:
            _fail("Every firmware entry requires source provenance.")
        sources = tuple(_source(_object(source, "source")) for source in sources_raw)
        project = _string(value, "project")
        if any(source.project != project for source in sources):
            _fail("Firmware source project must match its catalog entry.")
        serialized = json.dumps(value).lower()
        if (
            "http://" in serialized
            or "https://" in serialized
            or any(suffix in serialized for suffix in (".bin", ".hex", ".fw"))
        ):
            _fail("Firmware catalog must not contain firmware binary URLs or paths.")
        requires_driver = value.get("requires_matching_chirp_driver")
        if not isinstance(requires_driver, bool):
            _fail("requires_matching_chirp_driver must be boolean.")
        status = _string(value, "status")
        risk = _string(value, "risk")
        if status not in KNOWN_PROJECT_STATUSES or risk not in KNOWN_RISKS:
            _fail("Firmware entry contains an unknown status or risk classification.")
        entries.append(
            FirmwareEntry(
                id=_string(value, "id"),
                name=_string(value, "name"),
                project=project,
                status=status,
                supported_mcus=mcus,
                supported_revisions=supported,
                unsupported_revisions=unsupported,
                requires_matching_chirp_driver=requires_driver,
                risk=risk,
                notes=_strings(value, "notes"),
                sources=sources,
            )
        )
    ids = [item.id for item in entries]
    if len(ids) != len(set(ids)):
        _fail("Firmware catalog IDs must be unique.")
    combinations: set[tuple[str, str]] = set()
    for entry in entries:
        for revision in entry.supported_revisions:
            combination = (entry.project, revision)
            if combination in combinations:
                _fail("Duplicate project/revision combination in firmware catalog.")
            combinations.add(combination)
    return FirmwareCatalog(
        CATALOG_SCHEMA_VERSION,
        version,
        generated_at,
        tuple(sorted(entries, key=lambda item: item.id)),
    )


def validate_catalogs() -> tuple[tuple[HardwareRecord, ...], FirmwareCatalog]:
    hardware = load_hardware_records()
    catalog = load_firmware_catalog()
    return hardware, catalog


__all__ = [
    "CatalogError",
    "CatalogSource",
    "FirmwareCatalog",
    "FirmwareEntry",
    "HardwareRecord",
    "KNOWN_MCUS",
    "load_firmware_catalog",
    "load_hardware_records",
    "validate_catalogs",
]
