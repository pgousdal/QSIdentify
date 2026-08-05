from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, NoReturn

from . import __version__
from .drivers import get_driver
from .evidence import FINGERPRINT_SCHEMA_VERSION, validate_bundle

REGISTRY_SCHEMA_VERSION = 1
MINIMUM_CORRELATION_DEVICES = 3
ALLOWED_VERIFICATION = {
    "unverified",
    "self-inspected",
    "independently-reviewed",
    "conflicting",
    "withdrawn",
}
FORBIDDEN_KEYS = {
    "hostname",
    "host_name",
    "username",
    "user_name",
    "home_directory",
    "usb_serial_number",
}


class RegistryError(ValueError):
    """Base error for deterministic offline registry operations."""


class RegistrySchemaError(RegistryError):
    """Raised for unsupported or malformed registry schemas."""


class DuplicateEvidenceError(RegistryError):
    """Raised when a bundle identity is already registered."""


class CandidateStatus(StrEnum):
    CANDIDATE = "candidate"
    INSUFFICIENT = "insufficient-evidence"
    CORRELATED = "correlated"
    CONTRADICTED = "contradicted"
    DEPRECATED = "deprecated"
    REJECTED = "rejected"
    VERIFIED = "verified-electronic-identifier"


@dataclass(frozen=True, slots=True)
class BundleRecord:
    bundle_id: str
    content_digest: str
    electronic_fingerprint: str
    fingerprint_schema: int
    driver_ids: tuple[str, ...]
    device_id: str | None
    capture_ids: tuple[str, ...]
    probe_run_ids: tuple[str, ...]
    canonical_bundle_json: str
    contribution_id: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    device_id: str
    label: str
    declared_model: str | None
    declared_revision: str | None
    declared_mcu: str | None
    declared_pcb: str | None
    electronic_fingerprints: tuple[str, ...]
    bundle_ids: tuple[str, ...]
    evidence_status: str


@dataclass(frozen=True, slots=True)
class DeclarationRecord:
    declaration_id: str
    device_id: str
    field: str
    value: str
    source: str
    timestamp: str
    confidence: str
    verification_status: str
    notes: str
    photograph_digest: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateRecord:
    candidate_id: str
    driver_id: str
    probe_definition: str
    offset: int
    length: int
    normalization_rules: tuple[str, ...]
    supporting_bundle_ids: tuple[str, ...]
    supporting_device_ids: tuple[str, ...]
    contradicting_bundle_ids: tuple[str, ...]
    observed_values: tuple[str, ...]
    declared_hardware_correlations: tuple[str, ...]
    sample_count: int
    device_count: int
    status: CandidateStatus
    confidence_scope: str
    review_history: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReviewEvent:
    sequence: int
    timestamp: str
    action: str
    subject_id: str
    detail: str


@dataclass(frozen=True, slots=True)
class Conflict:
    code: str
    severity: str
    subject_id: str
    device_ids: tuple[str, ...] = ()
    bundle_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EvidenceRegistry:
    schema_version: int
    registry_id: str
    created_utc: str
    updated_utc: str
    qsidentify_version: str
    bundles: tuple[BundleRecord, ...]
    devices: tuple[DeviceRecord, ...]
    declarations: tuple[DeclarationRecord, ...]
    candidates: tuple[CandidateRecord, ...]
    review_events: tuple[ReviewEvent, ...]
    registry_digest: str

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "bundle_records": [asdict(item) for item in self.bundles],
            "candidate_discriminator_records": [
                {**asdict(item), "status": item.status.value} for item in self.candidates
            ],
            "created_utc": self.created_utc,
            "declaration_records": [asdict(item) for item in self.declarations],
            "device_records": [asdict(item) for item in self.devices],
            "qsidentify_version": self.qsidentify_version,
            "registry_id": self.registry_id,
            "review_events": [asdict(item) for item in self.review_events],
            "schema_version": self.schema_version,
            "updated_utc": self.updated_utc,
        }
        if include_digest:
            payload["registry_digest"] = self.registry_digest
        return payload


@dataclass(frozen=True, slots=True)
class RegistryMutation:
    registry: EvidenceRegistry
    imported_bundle_ids: tuple[str, ...]
    skipped_bundle_ids: tuple[str, ...]
    relationships: tuple[str, ...]
    conflicts: tuple[Conflict, ...]


@dataclass(frozen=True, slots=True)
class RegistryValidation:
    valid: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical(value: object, *, pretty: bool = False) -> bytes:
    if pretty:
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc(value: str | None) -> str:
    if value is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError("Registry timestamps must be ISO-8601.") from exc
    if parsed.tzinfo is None:
        raise RegistryError("Registry timestamps must include a UTC offset.")
    return value


def _contains_forbidden(value: object) -> tuple[str, ...]:
    found: set[str] = set()

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                normalized = str(key).lower()
                if normalized in FORBIDDEN_KEYS:
                    found.add(normalized)
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, str):
            if item.startswith(("/home/", "C:\\Users\\")):
                found.add("absolute-home-path")

    visit(value)
    return tuple(sorted(found))


def _with_digest(registry: EvidenceRegistry) -> EvidenceRegistry:
    digest = "sha256:" + _sha(_canonical(registry.to_dict(include_digest=False)))
    return replace(registry, registry_digest=digest)


def create_registry(
    *, timestamp: str | None = None, registry_label: str = "default"
) -> EvidenceRegistry:
    created = _utc(timestamp)
    identity = _sha(_canonical({"created_utc": created, "label": registry_label}))
    return _with_digest(
        EvidenceRegistry(
            schema_version=REGISTRY_SCHEMA_VERSION,
            registry_id=f"registry:sha256:{identity}",
            created_utc=created,
            updated_utc=created,
            qsidentify_version=__version__,
            bundles=(),
            devices=(),
            declarations=(),
            candidates=(),
            review_events=(),
            registry_digest="",
        )
    )


def _fail(message: str) -> NoReturn:
    raise RegistrySchemaError(message)


def _tuple_strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _fail(f"Registry field '{field}' must be an array of strings.")
    return tuple(value)


def registry_from_dict(raw: object) -> EvidenceRegistry:
    if not isinstance(raw, dict):
        _fail("Registry must be a JSON object.")
    if raw.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        _fail(f"Unsupported evidence registry schema: {raw.get('schema_version')}")
    try:
        bundles = tuple(
            BundleRecord(
                bundle_id=item["bundle_id"],
                content_digest=item["content_digest"],
                electronic_fingerprint=item["electronic_fingerprint"],
                fingerprint_schema=item["fingerprint_schema"],
                driver_ids=_tuple_strings(item["driver_ids"], "driver_ids"),
                device_id=item["device_id"],
                capture_ids=_tuple_strings(item["capture_ids"], "capture_ids"),
                probe_run_ids=_tuple_strings(item["probe_run_ids"], "probe_run_ids"),
                canonical_bundle_json=item["canonical_bundle_json"],
                contribution_id=item.get("contribution_id"),
            )
            for item in raw["bundle_records"]
        )
        devices = tuple(
            DeviceRecord(
                device_id=item["device_id"],
                label=item["label"],
                declared_model=item["declared_model"],
                declared_revision=item["declared_revision"],
                declared_mcu=item["declared_mcu"],
                declared_pcb=item["declared_pcb"],
                electronic_fingerprints=_tuple_strings(
                    item["electronic_fingerprints"], "electronic_fingerprints"
                ),
                bundle_ids=_tuple_strings(item["bundle_ids"], "bundle_ids"),
                evidence_status=item["evidence_status"],
            )
            for item in raw["device_records"]
        )
        declarations = tuple(DeclarationRecord(**item) for item in raw["declaration_records"])
        candidates = tuple(
            CandidateRecord(
                candidate_id=item["candidate_id"],
                driver_id=item["driver_id"],
                probe_definition=item["probe_definition"],
                offset=item["offset"],
                length=item["length"],
                normalization_rules=_tuple_strings(
                    item["normalization_rules"], "normalization_rules"
                ),
                supporting_bundle_ids=_tuple_strings(
                    item["supporting_bundle_ids"], "supporting_bundle_ids"
                ),
                supporting_device_ids=_tuple_strings(
                    item["supporting_device_ids"], "supporting_device_ids"
                ),
                contradicting_bundle_ids=_tuple_strings(
                    item["contradicting_bundle_ids"], "contradicting_bundle_ids"
                ),
                observed_values=_tuple_strings(item["observed_values"], "observed_values"),
                declared_hardware_correlations=_tuple_strings(
                    item["declared_hardware_correlations"],
                    "declared_hardware_correlations",
                ),
                sample_count=item["sample_count"],
                device_count=item["device_count"],
                status=CandidateStatus(item["status"]),
                confidence_scope=item["confidence_scope"],
                review_history=_tuple_strings(item["review_history"], "review_history"),
            )
            for item in raw["candidate_discriminator_records"]
        )
        events = tuple(ReviewEvent(**item) for item in raw["review_events"])
        registry = EvidenceRegistry(
            schema_version=raw["schema_version"],
            registry_id=raw["registry_id"],
            created_utc=raw["created_utc"],
            updated_utc=raw["updated_utc"],
            qsidentify_version=raw["qsidentify_version"],
            bundles=bundles,
            devices=devices,
            declarations=declarations,
            candidates=candidates,
            review_events=events,
            registry_digest=raw["registry_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RegistrySchemaError(f"Malformed registry: {exc}") from exc
    return registry


def load_registry(path: Path) -> EvidenceRegistry:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"Unable to load registry: {exc}") from exc
    registry = registry_from_dict(raw)
    validation = validate_registry(registry)
    if not validation.valid:
        raise RegistrySchemaError("; ".join(validation.errors))
    return registry


def write_registry(path: Path, registry: EvidenceRegistry) -> None:
    validated = _with_digest(registry)
    result = validate_registry(validated)
    if not result.valid:
        raise RegistrySchemaError("; ".join(result.errors))
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical(validated.to_dict(), pretty=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical(value, pretty=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def validate_registry(registry: EvidenceRegistry) -> RegistryValidation:
    errors: list[str] = []
    warnings: list[str] = []
    if registry.schema_version != REGISTRY_SCHEMA_VERSION:
        errors.append("unsupported_registry_schema")
    identifiers = [item.bundle_id for item in registry.bundles]
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        errors.append("bundle_ids_not_unique_sorted")
    device_ids = [item.device_id for item in registry.devices]
    if device_ids != sorted(device_ids) or len(device_ids) != len(set(device_ids)):
        errors.append("device_ids_not_unique_sorted")
    candidate_ids = [item.candidate_id for item in registry.candidates]
    if candidate_ids != sorted(candidate_ids) or len(candidate_ids) != len(set(candidate_ids)):
        errors.append("candidate_ids_not_unique_sorted")
    expected = _with_digest(replace(registry, registry_digest="")).registry_digest
    if registry.registry_digest != expected:
        errors.append("registry_digest_mismatch")
    forbidden = _contains_forbidden(registry.to_dict())
    errors.extend(f"forbidden_metadata:{item}" for item in forbidden)
    for bundle in registry.bundles:
        try:
            value = json.loads(bundle.canonical_bundle_json)
        except json.JSONDecodeError:
            errors.append(f"invalid_bundle_json:{bundle.bundle_id}")
            continue
        if "sha256:" + _sha(_canonical(_content_projection(value))) != bundle.content_digest:
            errors.append(f"bundle_content_digest_mismatch:{bundle.bundle_id}")
        for driver_id in bundle.driver_ids:
            try:
                get_driver(driver_id)
            except KeyError:
                errors.append(f"unknown_driver:{driver_id}")
        if bundle.fingerprint_schema != FINGERPRINT_SCHEMA_VERSION:
            errors.append(f"unsupported_fingerprint_schema:{bundle.bundle_id}")
    for candidate in registry.candidates:
        if candidate.status is CandidateStatus.VERIFIED:
            errors.append(f"automatic_verified_status_forbidden:{candidate.candidate_id}")
    conflicts = detect_conflicts(registry)
    warnings.extend(item.code for item in conflicts if item.severity != "blocking")
    return RegistryValidation(not errors, tuple(sorted(set(errors))), tuple(sorted(set(warnings))))


def _content_projection(bundle: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in bundle.items() if key not in {"bundle_id"}}


def _bundle_record(
    path: Path,
    *,
    device_label: str | None,
    contribution_id: str | None,
) -> tuple[BundleRecord, DeviceRecord | None, tuple[DeclarationRecord, ...]]:
    ok, errors = validate_bundle(path)
    if not ok:
        raise RegistryError("Invalid evidence bundle: " + "; ".join(errors))
    raw = json.loads(path.read_text(encoding="utf-8"))
    source_labels = {
        str((capture.get("capture_metadata") or {}).get("physical_device_group"))
        for capture in raw.get("captures", [])
        if (capture.get("capture_metadata") or {}).get("physical_device_group")
    }
    if len(source_labels) > 1:
        raise RegistryError("bundle_multiple_source_devices")
    canonical_json = _canonical(raw).decode()
    content_digest = "sha256:" + _sha(_canonical(_content_projection(raw)))
    supplied_id = raw.get("bundle_id")
    bundle_id = supplied_id if isinstance(supplied_id, str) else f"bundle:{content_digest}"
    fingerprint = raw["fingerprint"]
    captures = raw["captures"]
    drivers = tuple(sorted({str(item["driver_id"]) for item in captures}))
    capture_ids = tuple(sorted("capture:sha256:" + _sha(_canonical(item)) for item in captures))
    probe_runs = tuple(
        sorted(
            {
                str((item.get("capture_metadata") or {}).get("experiment_id"))
                for item in captures
                if (item.get("capture_metadata") or {}).get("experiment_id")
            }
        )
    )
    inferred_label = device_label or _bundle_device_label(raw)
    device: DeviceRecord | None = None
    device_id: str | None = None
    if inferred_label:
        device_id = "device:sha256:" + _sha(_canonical({"label": inferred_label}))
        labels = _bundle_labels(raw)
        device = DeviceRecord(
            device_id=device_id,
            label=inferred_label,
            declared_model=labels.get("marketed_model"),
            declared_revision=labels.get("user_observed_revision_marking"),
            declared_mcu=labels.get("declared_mcu"),
            declared_pcb=labels.get("declared_pcb"),
            electronic_fingerprints=(fingerprint["fingerprint_id"],),
            bundle_ids=(bundle_id,),
            evidence_status="incomplete",
        )
    declarations = _declarations(raw, device_id)
    return (
        BundleRecord(
            bundle_id=bundle_id,
            content_digest=content_digest,
            electronic_fingerprint=fingerprint["fingerprint_id"],
            fingerprint_schema=int(fingerprint["schema_version"]),
            driver_ids=drivers,
            device_id=device_id,
            capture_ids=capture_ids,
            probe_run_ids=probe_runs,
            canonical_bundle_json=canonical_json,
            contribution_id=contribution_id,
        ),
        device,
        declarations,
    )


def _bundle_labels(bundle: dict[str, Any]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for capture in bundle.get("captures", []):
        metadata = capture.get("capture_metadata") or {}
        for key, value in metadata.items():
            if isinstance(value, str):
                labels[key] = value
    return labels


def _bundle_device_label(bundle: dict[str, Any]) -> str | None:
    labels = _bundle_labels(bundle)
    return labels.get("physical_device_group") or labels.get("device_alias")


def _declarations(bundle: dict[str, Any], device_id: str | None) -> tuple[DeclarationRecord, ...]:
    raw_items = bundle.get("declarations", [])
    if not raw_items or device_id is None:
        return ()
    records: list[DeclarationRecord] = []
    for item in raw_items:
        if not isinstance(item, dict):
            raise RegistryError("Declaration must be an object.")
        status = item.get("verification_status", "unverified")
        if status not in ALLOWED_VERIFICATION:
            raise RegistryError(f"Unknown declaration verification status: {status}")
        projection = {**item, "device_id": device_id}
        declaration_id = "declaration:sha256:" + _sha(_canonical(projection))
        try:
            records.append(
                DeclarationRecord(
                    declaration_id=declaration_id,
                    device_id=device_id,
                    field=str(item["field"]),
                    value=str(item["value"]),
                    source=str(item["source"]),
                    timestamp=_utc(str(item["timestamp"])),
                    confidence=str(item.get("confidence", "user-supplied")),
                    verification_status=str(status),
                    notes=str(item.get("notes", "")),
                    photograph_digest=item.get("photograph_digest"),
                )
            )
        except KeyError as exc:
            raise RegistryError(f"Missing declaration field: {exc}") from exc
    return tuple(sorted(records, key=lambda item: item.declaration_id))


def _merge_device(existing: DeviceRecord, incoming: DeviceRecord) -> DeviceRecord:
    return replace(
        existing,
        electronic_fingerprints=tuple(
            sorted(set(existing.electronic_fingerprints + incoming.electronic_fingerprints))
        ),
        bundle_ids=tuple(sorted(set(existing.bundle_ids + incoming.bundle_ids))),
        declared_model=existing.declared_model or incoming.declared_model,
        declared_revision=existing.declared_revision or incoming.declared_revision,
        declared_mcu=existing.declared_mcu or incoming.declared_mcu,
        declared_pcb=existing.declared_pcb or incoming.declared_pcb,
    )


def _apply_declarations(
    device: DeviceRecord, declarations: tuple[DeclarationRecord, ...]
) -> DeviceRecord:
    active = [item for item in declarations if item.verification_status != "withdrawn"]

    def single(*fields: str) -> str | None:
        values = sorted({item.value for item in active if item.field in fields})
        return values[0] if len(values) == 1 else None

    return replace(
        device,
        declared_model=single("marketing_model", "model") or device.declared_model,
        declared_revision=single("hardware_revision", "revision") or device.declared_revision,
        declared_mcu=single("mcu", "mcu_marking") or device.declared_mcu,
        declared_pcb=single("pcb_revision", "pcb_text") or device.declared_pcb,
    )


def add_evidence_bundle(
    registry: EvidenceRegistry,
    bundle_path: Path,
    *,
    device_label: str | None = None,
    contribution_id: str | None = None,
    timestamp: str | None = None,
    reject_duplicates: bool = True,
) -> RegistryMutation:
    record, device, declarations = _bundle_record(
        bundle_path, device_label=device_label, contribution_id=contribution_id
    )
    by_id = {item.bundle_id: item for item in registry.bundles}
    if record.bundle_id in by_id:
        if reject_duplicates:
            raise DuplicateEvidenceError(f"Duplicate bundle ID: {record.bundle_id}")
        return RegistryMutation(registry, (), (record.bundle_id,), ("exact duplicate",), ())
    relationships: list[str] = []
    for item in registry.bundles:
        if item.content_digest == record.content_digest:
            relationships.append("content duplicate")
        if item.electronic_fingerprint == record.electronic_fingerprint:
            relationships.append("same fingerprint")
        if set(item.capture_ids) == set(record.capture_ids):
            relationships.append("probable same evidence set")
    if not relationships:
        relationships.append("distinct evidence")
    devices = {item.device_id: item for item in registry.devices}
    if device is not None:
        device = _apply_declarations(device, declarations)
        devices[device.device_id] = (
            _merge_device(devices[device.device_id], device)
            if device.device_id in devices
            else device
        )
    event_time = _utc(timestamp)
    event = ReviewEvent(
        sequence=len(registry.review_events) + 1,
        timestamp=event_time,
        action="bundle-added",
        subject_id=record.bundle_id,
        detail=",".join(sorted(set(relationships))),
    )
    updated = _with_digest(
        replace(
            registry,
            updated_utc=event_time,
            qsidentify_version=__version__,
            bundles=tuple(sorted((*registry.bundles, record), key=lambda item: item.bundle_id)),
            devices=tuple(sorted(devices.values(), key=lambda item: item.device_id)),
            declarations=tuple(
                sorted(
                    {
                        item.declaration_id: item
                        for item in (*registry.declarations, *declarations)
                    }.values(),
                    key=lambda item: item.declaration_id,
                )
            ),
            review_events=(*registry.review_events, event),
        )
    )
    conflicts = detect_conflicts(updated)
    if conflicts:
        relationships.append("conflicting declarations")
    return RegistryMutation(
        updated,
        (record.bundle_id,),
        (),
        tuple(sorted(set(relationships))),
        conflicts,
    )


def remove_evidence_bundle(
    registry: EvidenceRegistry, bundle_id: str, *, timestamp: str | None = None
) -> EvidenceRegistry:
    if bundle_id not in {item.bundle_id for item in registry.bundles}:
        raise RegistryError(f"Unknown bundle ID: {bundle_id}")
    now = _utc(timestamp)
    devices = tuple(
        replace(item, bundle_ids=tuple(value for value in item.bundle_ids if value != bundle_id))
        for item in registry.devices
    )
    event = ReviewEvent(
        len(registry.review_events) + 1,
        now,
        "bundle-removed",
        bundle_id,
        "Evidence removed; audit event retained.",
    )
    return _with_digest(
        replace(
            registry,
            updated_utc=now,
            bundles=tuple(item for item in registry.bundles if item.bundle_id != bundle_id),
            devices=devices,
            review_events=(*registry.review_events, event),
        )
    )


def detect_conflicts(registry: EvidenceRegistry) -> tuple[Conflict, ...]:
    conflicts: list[Conflict] = []
    active = [item for item in registry.declarations if item.verification_status != "withdrawn"]
    for device in registry.devices:
        declarations = [item for item in active if item.device_id == device.device_id]
        for field, code in (
            ("mcu", "device_mcu_conflict"),
            ("pcb_revision", "device_pcb_conflict"),
        ):
            values = {item.value for item in declarations if item.field == field}
            if len(values) > 1:
                conflicts.append(Conflict(code, "blocking", device.device_id, (device.device_id,)))
        evidence_times: list[datetime] = []
        related_bundles = [item for item in registry.bundles if item.device_id == device.device_id]
        for bundle in related_bundles:
            for capture in _bundle_object(bundle).get("captures", []):
                try:
                    evidence_times.append(datetime.fromisoformat(capture["created_utc"]))
                except (KeyError, TypeError, ValueError):
                    continue
        if evidence_times:
            first_evidence = min(evidence_times)
            for declaration in declarations:
                declared_at = datetime.fromisoformat(declaration.timestamp)
                if declared_at < first_evidence:
                    conflicts.append(
                        Conflict(
                            "declaration_precedes_evidence",
                            "blocking",
                            declaration.declaration_id,
                            (device.device_id,),
                            tuple(item.bundle_id for item in related_bundles),
                        )
                    )
    fingerprint_devices: dict[str, set[str]] = {}
    for bundle in registry.bundles:
        if bundle.device_id:
            fingerprint_devices.setdefault(bundle.electronic_fingerprint, set()).add(
                bundle.device_id
            )
    for fingerprint, device_ids in fingerprint_devices.items():
        inspected: dict[str, set[str]] = {}
        for declaration in active:
            if (
                declaration.device_id in device_ids
                and declaration.verification_status
                in {
                    "self-inspected",
                    "independently-reviewed",
                }
                and declaration.field in {"mcu", "pcb_revision"}
            ):
                inspected.setdefault(declaration.field, set()).add(declaration.value)
        if any(len(values) > 1 for values in inspected.values()):
            conflicts.append(
                Conflict(
                    "fingerprint_hardware_conflict",
                    "blocking",
                    fingerprint,
                    tuple(sorted(device_ids)),
                )
            )
    return tuple(sorted(conflicts, key=lambda item: (item.code, item.subject_id)))


def _bundle_object(record: BundleRecord) -> dict[str, Any]:
    value = json.loads(record.canonical_bundle_json)
    if not isinstance(value, dict):
        raise RegistrySchemaError(f"Bundle {record.bundle_id} is not an object.")
    return value


def analyze_registry(registry: EvidenceRegistry) -> dict[str, Any]:
    captures: list[dict[str, Any]] = []
    responses: list[bytes] = []
    firmware: dict[str, int] = {}
    fingerprints: dict[str, int] = {}
    drivers: dict[str, int] = {}
    checksums: dict[str, int] = {}
    commands: dict[str, int] = {}
    probes: dict[str, int] = {}
    response_lengths: dict[str, int] = {}
    stable_masks: dict[str, int] = {}
    for record in registry.bundles:
        fingerprints[record.electronic_fingerprint] = (
            fingerprints.get(record.electronic_fingerprint, 0) + 1
        )
        bundle = _bundle_object(record)
        fingerprint = bundle.get("fingerprint", {})
        for response_length in fingerprint.get("response_lengths", []):
            key = str(response_length)
            response_lengths[key] = response_lengths.get(key, 0) + 1
        mask = str(fingerprint.get("stable_payload_mask_hex", ""))
        if mask:
            stable_masks[mask] = stable_masks.get(mask, 0) + 1
        for capture in bundle.get("captures", []):
            captures.append(capture)
            response = bytes.fromhex(capture["raw_response_hex"])
            responses.append(response)
            report = capture["probe_report"]
            version = report.get("reported_version") or "unknown"
            firmware[version] = firmware.get(version, 0) + 1
            driver = capture["driver_id"]
            drivers[driver] = drivers.get(driver, 0) + 1
            status = str(bundle.get("fingerprint", {}).get("checksum_behaviors", ["unknown"])[0])
            checksums[status] = checksums.get(status, 0) + 1
            command = capture.get("safety", {}).get("command") or "passive"
            commands[command] = commands.get(command, 0) + 1
            probe = (capture.get("capture_metadata") or {}).get("experiment_id") or "unspecified"
            probes[str(probe)] = probes.get(str(probe), 0) + 1
    width = max((len(item) for item in responses), default=0)
    stable: list[int] = []
    variable: list[int] = []
    for offset in range(width):
        observed = [item[offset] for item in responses if offset < len(item)]
        if observed and len(observed) == len(responses) and len(set(observed)) == 1:
            stable.append(offset)
        else:
            variable.append(offset)
    prefix = _common_edge(responses, from_end=False)
    suffix = _common_edge(responses, from_end=True)
    zero_count = sum(response.count(0) for response in responses)
    byte_count = sum(len(response) for response in responses)
    device_stability: dict[str, dict[str, list[int]]] = {}
    device_values: dict[str, list[bytes]] = {}
    for record in registry.bundles:
        if record.device_id:
            device_values.setdefault(record.device_id, []).extend(
                bytes.fromhex(capture["raw_response_hex"])
                for capture in _bundle_object(record).get("captures", [])
            )
    for device_id, observed_responses in sorted(device_values.items()):
        device_width = max((len(item) for item in observed_responses), default=0)
        device_stable: list[int] = []
        device_variable: list[int] = []
        for offset in range(device_width):
            observed = [item[offset] for item in observed_responses if offset < len(item)]
            target = (
                device_stable
                if len(observed) == len(observed_responses) and len(set(observed)) == 1
                else device_variable
            )
            target.append(offset)
        device_stability[device_id] = {
            "stable_byte_positions": device_stable,
            "variable_byte_positions": device_variable,
        }
    between_device_variable: list[int] = []
    if len(device_values) > 1:
        device_width = min(max(len(item) for item in values) for values in device_values.values())
        for offset in range(device_width):
            per_device: list[int] = []
            eligible = True
            for values in device_values.values():
                observed = [item[offset] for item in values if offset < len(item)]
                if len(observed) != len(values) or len(set(observed)) != 1:
                    eligible = False
                    break
                per_device.append(observed[0])
            if eligible and len(set(per_device)) > 1:
                between_device_variable.append(offset)

    def declared_group(field: str) -> dict[str, int]:
        grouped: dict[str, int] = {}
        for device in registry.devices:
            value = getattr(device, field) or "unknown"
            grouped[value] = grouped.get(value, 0) + 1
        return dict(sorted(grouped.items()))

    return {
        "bundle_count": len(registry.bundles),
        "capture_count": len(captures),
        "checksum_behavior": dict(sorted(checksums.items())),
        "command_groups": dict(sorted(commands.items())),
        "common_prefix_length": prefix,
        "common_suffix_length": suffix,
        "device_count": len(registry.devices),
        "declared_mcu_groups": declared_group("declared_mcu"),
        "declared_model_groups": declared_group("declared_model"),
        "declared_pcb_groups": declared_group("declared_pcb"),
        "device_stability": device_stability,
        "driver_groups": dict(sorted(drivers.items())),
        "exact_response_count": len(responses),
        "fingerprint_groups": dict(sorted(fingerprints.items())),
        "firmware_groups": dict(sorted(firmware.items())),
        "legacy_checksum_frequency": checksums.get("accepted-legacy-ff-ff", 0),
        "null_byte_percentage": round((zero_count / byte_count * 100) if byte_count else 0.0, 3),
        "probe_count": sum(probes.values()),
        "probe_groups": dict(sorted(probes.items())),
        "response_length_groups": dict(sorted(response_lengths.items())),
        "stable_byte_positions": stable,
        "stable_mask_groups": dict(sorted(stable_masks.items())),
        "unique_fingerprint_count": len(fingerprints),
        "unique_response_count": len(set(responses)),
        "variable_byte_positions": variable,
        "between_device_variable_positions": between_device_variable,
        "verified_crc_frequency": checksums.get("valid", 0),
    }


def _common_edge(values: list[bytes], *, from_end: bool) -> int:
    if not values:
        return 0
    limit = min(len(item) for item in values)
    count = 0
    for index in range(limit):
        offset = -(index + 1) if from_end else index
        if len({item[offset] for item in values}) != 1:
            break
        count += 1
    return count


def propose_discriminator(
    registry: EvidenceRegistry,
    *,
    offset: int,
    length: int,
    driver_id: str,
    probe_definition: str = "firmware-identification",
    timestamp: str | None = None,
) -> EvidenceRegistry:
    if offset < 0 or length < 1 or length > 32:
        raise RegistryError("Discriminator offset/length is outside the safe analysis range.")
    values: dict[str, list[str]] = {}
    supporting_bundles: list[str] = []
    supporting_devices: set[str] = set()
    contradicting_bundles: set[str] = set()
    samples = 0
    for record in registry.bundles:
        if record.driver_ids != (driver_id,):
            continue
        bundle = _bundle_object(record)
        bundle_values: set[str] = set()
        for capture in bundle.get("captures", []):
            if capture["driver_id"] != driver_id:
                continue
            command = capture.get("safety", {}).get("command") or "passive"
            if probe_definition == "firmware-identification" and command != "identify-handshake":
                contradicting_bundles.add(record.bundle_id)
                continue
            payload = bytes.fromhex(capture.get("decoded_payload_hex", ""))
            if not payload:
                frames = capture.get("decoded_valid_frames_hex", [])
                if frames:
                    # Region is defined over the decoded payload exposed by the bundle report.
                    payload = bytes.fromhex(bundle["fingerprint"]["stable_payload_values_hex"])
            if offset + length <= len(payload):
                bundle_values.add(payload[offset : offset + length].hex())
                samples += 1
        if bundle_values:
            supporting_bundles.append(record.bundle_id)
            if record.device_id:
                supporting_devices.add(record.device_id)
            for value in bundle_values:
                values.setdefault(value, []).append(record.bundle_id)
    correlations = _candidate_correlations(registry, values, offset, length)
    conflicts = detect_conflicts(registry)
    device_count = len(supporting_devices)
    status = CandidateStatus.INSUFFICIENT
    if conflicts or contradicting_bundles:
        status = CandidateStatus.CONTRADICTED
    elif device_count >= MINIMUM_CORRELATION_DEVICES and correlations:
        status = CandidateStatus.CORRELATED
    elif samples and device_count >= 2:
        status = CandidateStatus.CANDIDATE
    projection = {
        "driver_id": driver_id,
        "length": length,
        "offset": offset,
        "probe_definition": probe_definition,
    }
    candidate_id = "candidate:sha256:" + _sha(_canonical(projection))
    candidate = CandidateRecord(
        candidate_id=candidate_id,
        driver_id=driver_id,
        probe_definition=probe_definition,
        offset=offset,
        length=length,
        normalization_rules=("decoded-payload", "exact-byte-region"),
        supporting_bundle_ids=tuple(sorted(supporting_bundles)),
        supporting_device_ids=tuple(sorted(supporting_devices)),
        contradicting_bundle_ids=tuple(
            sorted(
                contradicting_bundles | {bundle for item in conflicts for bundle in item.bundle_ids}
            )
        ),
        observed_values=tuple(sorted(values)),
        declared_hardware_correlations=tuple(sorted(correlations)),
        sample_count=samples,
        device_count=device_count,
        status=status,
        confidence_scope="statistical-correlation-only",
        review_history=("Automatic analysis cannot verify a hardware identifier.",),
    )
    now = _utc(timestamp)
    event = ReviewEvent(
        len(registry.review_events) + 1,
        now,
        "candidate-proposed",
        candidate_id,
        status.value,
    )
    candidates = {item.candidate_id: item for item in registry.candidates}
    candidates[candidate_id] = candidate
    return _with_digest(
        replace(
            registry,
            updated_utc=now,
            candidates=tuple(sorted(candidates.values(), key=lambda item: item.candidate_id)),
            review_events=(*registry.review_events, event),
        )
    )


def _candidate_correlations(
    registry: EvidenceRegistry,
    values: dict[str, list[str]],
    offset: int,
    length: int,
) -> set[str]:
    correlations: set[str] = set()
    if len(values) < 2:
        return correlations
    active = [
        item
        for item in registry.declarations
        if item.verification_status in {"self-inspected", "independently-reviewed"}
        and item.field in {"mcu", "pcb_revision", "hardware_revision"}
    ]
    groups = {(item.field, item.value) for item in active}
    if len(groups) >= 2:
        correlations.add(f"region:{offset}:{length}:correlates-with-declared-groups")
    return correlations


def registry_matrix(registry: EvidenceRegistry) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for device in registry.devices:
        bundles = [item for item in registry.bundles if item.device_id == device.device_id]
        firmware = sorted(
            {
                version
                for bundle in bundles
                for version in _bundle_object(bundle)["fingerprint"].get("firmware_strings", [])
            }
        )
        rows.append(
            {
                "declared_mcu": device.declared_mcu,
                "declared_model": device.declared_model,
                "declared_pcb": device.declared_pcb,
                "device_id": device.device_id,
                "fingerprints": sorted(device.electronic_fingerprints),
                "firmware": firmware,
                "label": device.label,
            }
        )
    return tuple(rows)


def catalog_proposal(registry: EvidenceRegistry) -> dict[str, Any]:
    conflicts = detect_conflicts(registry)
    return {
        "blocking_conflicts": [item.to_dict() for item in conflicts if item.severity == "blocking"],
        "candidate_hardware_mappings": [],
        "candidates": [
            {
                **asdict(item),
                "status": item.status.value,
                "limitations": [
                    "Statistical correlation is not an electronic hardware identity.",
                    "Production catalogs are not modified by this proposal.",
                ],
                "required_manual_review": [
                    "Verify independent physical inspections.",
                    "Review contradictions and provenance.",
                    "Document criteria before any verified status change.",
                ],
            }
            for item in registry.candidates
        ],
        "generated_by": "qsidentify-registry-offline",
        "registry_digest": registry.registry_digest,
        "suggested_documentation_changes": [
            "Record sample counts and unresolved hardware properties."
        ],
    }


__all__ = [
    "BundleRecord",
    "CandidateRecord",
    "CandidateStatus",
    "Conflict",
    "DeclarationRecord",
    "DeviceRecord",
    "DuplicateEvidenceError",
    "EvidenceRegistry",
    "MINIMUM_CORRELATION_DEVICES",
    "REGISTRY_SCHEMA_VERSION",
    "RegistryError",
    "RegistryMutation",
    "RegistrySchemaError",
    "RegistryValidation",
    "add_evidence_bundle",
    "analyze_registry",
    "catalog_proposal",
    "create_registry",
    "detect_conflicts",
    "load_registry",
    "propose_discriminator",
    "registry_from_dict",
    "registry_matrix",
    "remove_evidence_bundle",
    "validate_registry",
    "write_registry",
    "write_json_atomic",
]
