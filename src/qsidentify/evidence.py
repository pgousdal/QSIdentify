from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from enum import StrEnum
from importlib.resources import files
from pathlib import Path
from typing import Any

from . import __version__
from .capture import read_capture
from .drivers import get_driver
from .hardening import sanitize_capture
from .models import Capture

FINGERPRINT_SCHEMA_VERSION = 1
DISCRIMINATOR_CATALOG_SCHEMA_VERSION = 1


class EvidenceError(ValueError):
    """Raised when curated evidence data or input captures are invalid."""


class ScopedConfidence(StrEnum):
    CONFIRMED = "confirmed"
    STRONG = "strong"
    TENTATIVE = "tentative"
    USER_SUPPLIED = "user-supplied"
    CONFLICTING = "conflicting"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CommandDescriptor:
    command_id: str
    symbolic_name: str
    request_type: str
    response_type: str
    safety_class: str
    read_only: bool
    allowlisted: bool
    evidence_categories: tuple[str, ...]
    minimum_request: str | None
    expected_response_lengths: tuple[int, ...]
    notes: tuple[str, ...]
    provenance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProbeDefinition:
    id: str
    name: str
    driver_id: str
    commands: tuple[str, ...]
    repeat_count: int
    evidence_targets: tuple[str, ...]
    experimental: bool
    enabled_by_default: bool
    available: bool
    safety_notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StabilityAnalysis:
    capture_count: int
    payload_lengths: tuple[int, ...]
    response_lengths: tuple[int, ...]
    stable_payload_values: bytes
    stable_payload_mask: bytes
    stable_positions: tuple[int, ...]
    variable_positions: tuple[int, ...]
    message_types: tuple[str, ...]
    firmware_strings: tuple[str, ...]
    checksum_behaviors: tuple[str, ...]
    printable_strings: tuple[str, ...]
    timing_offsets_ms: tuple[float, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_count": self.capture_count,
            "checksum_behaviors": list(self.checksum_behaviors),
            "firmware_strings": list(self.firmware_strings),
            "field_classifications": {
                "monotonic": [],
                "nonce-like": [],
                "stable": list(self.stable_positions),
                "timestamp-like": [],
                "unknown": list(self.variable_positions),
                "variable": list(self.variable_positions),
            },
            "message_types": list(self.message_types),
            "payload_lengths": list(self.payload_lengths),
            "printable_strings": list(self.printable_strings),
            "response_lengths": list(self.response_lengths),
            "stable_payload_mask_hex": self.stable_payload_mask.hex(),
            "stable_payload_values_hex": self.stable_payload_values.hex(),
            "stable_positions": list(self.stable_positions),
            "timing_offsets_ms": list(self.timing_offsets_ms),
            "variable_positions": list(self.variable_positions),
        }


@dataclass(frozen=True, slots=True)
class ElectronicFingerprint:
    schema_version: int
    driver_id: str
    protocol_family: str | None
    message_types: tuple[str, ...]
    firmware_strings: tuple[str, ...]
    stable_payload_mask_hex: str
    stable_payload_values_hex: str
    response_lengths: tuple[int, ...]
    checksum_behaviors: tuple[str, ...]
    bootloader_evidence: bool
    capability_evidence: bool
    timing_profile: dict[str, float | int | None]
    fingerprint_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _data(name: str) -> dict[str, Any]:
    resource = files("qsidentify.drivers.quansheng.data").joinpath(name)
    value = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError(f"{name} must contain a JSON object.")
    return value


def load_command_inventory() -> tuple[CommandDescriptor, ...]:
    raw = _data("command_inventory.json")
    if raw.get("schema_version") != 1 or not isinstance(raw.get("commands"), list):
        raise EvidenceError("Unsupported or malformed command inventory.")
    commands: list[CommandDescriptor] = []
    for item in raw["commands"]:
        try:
            descriptor = CommandDescriptor(
                command_id=str(item["command_id"]),
                symbolic_name=str(item["symbolic_name"]),
                request_type=str(item["request_type"]),
                response_type=str(item["response_type"]),
                safety_class=str(item["safety_class"]),
                read_only=bool(item["read_only"]),
                allowlisted=bool(item["allowlisted"]),
                evidence_categories=tuple(item["evidence_categories"]),
                minimum_request=item["minimum_request"],
                expected_response_lengths=tuple(item["expected_response_lengths"]),
                notes=tuple(item["notes"]),
                provenance=tuple(item["provenance"]),
            )
        except (KeyError, TypeError) as exc:
            raise EvidenceError("Malformed command inventory entry.") from exc
        if descriptor.allowlisted and (
            not descriptor.read_only
            or descriptor.safety_class not in {"identification-read", "metadata-read", "state-read"}
            or not descriptor.minimum_request
            or not descriptor.provenance
        ):
            raise EvidenceError(f"Unsafe allowlisted command: {descriptor.command_id}")
        commands.append(descriptor)
    if len({item.command_id for item in commands}) != len(commands):
        raise EvidenceError("Duplicate command inventory ID.")
    return tuple(sorted(commands, key=lambda item: item.command_id))


def load_probe_definitions() -> tuple[ProbeDefinition, ...]:
    raw = _data("probe_definitions.json")
    if raw.get("schema_version") != 1 or not isinstance(raw.get("probes"), list):
        raise EvidenceError("Unsupported or malformed probe definitions.")
    inventory = {item.command_id: item for item in load_command_inventory()}
    probes: list[ProbeDefinition] = []
    for item in raw["probes"]:
        try:
            probe = ProbeDefinition(
                id=str(item["id"]),
                name=str(item["name"]),
                driver_id=str(item["driver_id"]),
                commands=tuple(item["commands"]),
                repeat_count=int(item["repeat_count"]),
                evidence_targets=tuple(item["evidence_targets"]),
                experimental=bool(item["experimental"]),
                enabled_by_default=bool(item["enabled_by_default"]),
                available=bool(item.get("available", True)),
                safety_notes=tuple(item["safety_notes"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError("Malformed probe definition.") from exc
        if probe.repeat_count < 1 or probe.repeat_count > 20:
            raise EvidenceError(f"Unsafe repeat count for probe {probe.id}.")
        if probe.available and any(
            command not in inventory or not inventory[command].allowlisted
            for command in probe.commands
        ):
            raise EvidenceError(f"Probe {probe.id} contains a non-allowlisted command.")
        probes.append(probe)
    if len({item.id for item in probes}) != len(probes):
        raise EvidenceError("Duplicate probe definition ID.")
    return tuple(sorted(probes, key=lambda item: item.id))


def load_discriminators() -> tuple[dict[str, Any], ...]:
    raw = _data("hardware_discriminators.json")
    if raw.get("schema_version") != DISCRIMINATOR_CATALOG_SCHEMA_VERSION:
        raise EvidenceError("Unsupported discriminator catalog schema.")
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise EvidenceError("Malformed discriminator catalog.")
    allowed = {
        "candidate",
        "observed-repeatable",
        "externally-documented",
        "verified-discriminator",
        "rejected",
    }
    result: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("status") not in allowed:
            raise EvidenceError("Malformed discriminator entry.")
        if entry.get("status") != "verified-discriminator" and entry.get("maps_to"):
            raise EvidenceError("Only verified discriminators may map hardware identities.")
        result.append(entry)
    return tuple(sorted(result, key=lambda item: str(item["id"])))


def analyze_stability(captures: tuple[Capture, ...]) -> StabilityAnalysis:
    payloads = [
        bytes.fromhex(capture.decoded_payload_hex)
        for capture in captures
        if capture.decoded_payload_hex
    ]
    width = max((len(payload) for payload in payloads), default=0)
    values = bytearray(width)
    mask = bytearray(width)
    stable: list[int] = []
    variable: list[int] = []
    for offset in range(width):
        observed = [payload[offset] for payload in payloads if offset < len(payload)]
        if len(observed) == len(payloads) and observed and len(set(observed)) == 1:
            values[offset] = observed[0]
            mask[offset] = 0xFF
            stable.append(offset)
        else:
            variable.append(offset)
    printable: set[str] = set()
    for payload in payloads:
        for part in payload.split(b"\0"):
            if len(part) >= 3 and all(32 <= byte < 127 for byte in part):
                printable.add(part.decode("ascii"))
    checksums = {
        capture.checksum_status.value for capture in captures if capture.checksum_status is not None
    }
    return StabilityAnalysis(
        capture_count=len(captures),
        payload_lengths=tuple(sorted({len(item) for item in payloads})),
        response_lengths=tuple(
            sorted({len(bytes.fromhex(item.raw_response_hex)) for item in captures})
        ),
        stable_payload_values=bytes(values),
        stable_payload_mask=bytes(mask),
        stable_positions=tuple(stable),
        variable_positions=tuple(variable),
        message_types=tuple(sorted({item.report.message_type.value for item in captures})),
        firmware_strings=tuple(
            sorted(
                {item.report.reported_version for item in captures if item.report.reported_version}
            )
        ),
        checksum_behaviors=tuple(sorted(checksums)),
        printable_strings=tuple(sorted(printable)),
        timing_offsets_ms=tuple(
            round(chunk.monotonic_offset_ms, 3) for item in captures for chunk in item.read_chunks
        ),
    )


def build_fingerprint(captures: tuple[Capture, ...]) -> ElectronicFingerprint:
    if not captures:
        raise EvidenceError("At least one capture is required.")
    drivers = {capture.driver_id for capture in captures}
    if len(drivers) != 1:
        raise EvidenceError("A fingerprint cannot combine different drivers.")
    stability = analyze_stability(captures)
    protocol = next(
        (item.report.detected_protocol for item in captures if item.report.detected_protocol), None
    )
    contribution = {
        "bootloader_evidence": "bootloader-response" in stability.message_types,
        "capability_evidence": False,
        "checksum_behaviors": list(stability.checksum_behaviors),
        "driver_id": next(iter(drivers)),
        "firmware_strings": list(stability.firmware_strings),
        "message_types": list(stability.message_types),
        "protocol_family": protocol,
        "response_lengths": list(stability.response_lengths),
        "schema_version": FINGERPRINT_SCHEMA_VERSION,
        "stable_payload_mask_hex": stability.stable_payload_mask.hex(),
        "stable_payload_values_hex": stability.stable_payload_values.hex(),
    }
    digest = hashlib.sha256(
        json.dumps(contribution, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ElectronicFingerprint(
        schema_version=FINGERPRINT_SCHEMA_VERSION,
        driver_id=next(iter(drivers)),
        protocol_family=protocol,
        message_types=stability.message_types,
        firmware_strings=stability.firmware_strings,
        stable_payload_mask_hex=stability.stable_payload_mask.hex(),
        stable_payload_values_hex=stability.stable_payload_values.hex(),
        response_lengths=stability.response_lengths,
        checksum_behaviors=stability.checksum_behaviors,
        bootloader_evidence="bootloader-response" in stability.message_types,
        capability_evidence=False,
        timing_profile={
            "maximum_offset_ms": max(stability.timing_offsets_ms, default=None),
            "minimum_offset_ms": min(stability.timing_offsets_ms, default=None),
            "sample_count": len(stability.timing_offsets_ms),
        },
        fingerprint_id=f"qsfingerprint:v1:sha256:{digest}",
    )


def evidence_report(captures: tuple[Capture, ...]) -> dict[str, Any]:
    stability = analyze_stability(captures)
    fingerprint = build_fingerprint(captures)
    labels: dict[str, str] = {}
    allowed_labels = {
        "device_alias",
        "marketed_model",
        "production_sticker",
        "boot_screen_text",
        "menu_range",
        "user_observed_revision_marking",
        "physical_device_group",
        "experiment_id",
    }
    for capture in captures:
        for key, value in (capture.capture_metadata or {}).items():
            if key in allowed_labels and isinstance(value, str):
                labels[key] = value
    confidence = {
        "bootloader": "confirmed" if fingerprint.bootloader_evidence else "unknown",
        "firmware": "confirmed" if stability.firmware_strings else "unknown",
        "firmware_compatibility": "unknown",
        "hardware_revision": "unknown",
        "marketed_model": "user-supplied" if "marketed_model" in labels else "unknown",
        "mcu": "unknown",
        "model_family": "strong" if fingerprint.protocol_family else "unknown",
        "pcb_revision": "unknown",
        "protocol": "confirmed" if fingerprint.protocol_family else "unknown",
        "transport": "confirmed" if captures else "unknown",
    }
    return {
        "candidate_discriminators": [
            dict(item, experimental=True)
            for item in load_discriminators()
            if item["status"] != "rejected"
        ],
        "confidence": confidence,
        "fingerprint": fingerprint.to_dict(),
        "inferred": [
            "Captures may share a protocol implementation; no hardware mapping is established."
        ],
        "observed": stability.to_dict(),
        "unresolved": [
            "marketed-model",
            "hardware-revision",
            "mcu",
            "pcb-revision",
            "flash-size",
            "bootloader-revision",
        ],
        "user_supplied_labels": dict(sorted(labels.items())),
    }


def report_paths(paths: tuple[Path, ...]) -> dict[str, Any]:
    return evidence_report(tuple(read_capture(path) for path in paths))


def compare_evidence(captures: tuple[Capture, ...]) -> dict[str, Any]:
    report = evidence_report(captures)
    observed = report["observed"]
    groups: dict[str, list[Capture]] = {}
    for index, capture in enumerate(captures, start=1):
        metadata = capture.capture_metadata or {}
        group = metadata.get("physical_device_group") or metadata.get("device_alias")
        key = str(group) if group else f"capture-{index}"
        groups.setdefault(key, []).append(capture)
    group_stability = {
        key: analyze_stability(tuple(value)) for key, value in sorted(groups.items())
    }
    device_specific: list[dict[str, Any]] = []
    if len(group_stability) > 1:
        common_offsets = set.intersection(
            *(set(item.stable_positions) for item in group_stability.values())
        )
        for offset in sorted(common_offsets):
            values = {
                key: item.stable_payload_values[offset]
                for key, item in group_stability.items()
                if offset < len(item.stable_payload_values)
            }
            if len(set(values.values())) > 1:
                device_specific.append({"experimental": True, "offset": offset, "values": values})
    return {
        "candidate_discriminators": report["candidate_discriminators"],
        "device_specific_stable_fields": device_specific,
        "firmware_differences": observed["firmware_strings"],
        "per_run_variable_fields": observed["variable_positions"],
        "protocol_differences": observed["message_types"],
        "shared_stable_fields": observed["stable_positions"],
    }


def export_bundle(
    paths: tuple[Path, ...], output: Path, provenance_notes: str = ""
) -> dict[str, Any]:
    captures = tuple(sanitize_capture(read_capture(path))[0] for path in paths)
    manifest = [
        {
            "capture_index": index,
            "driver_id": capture.driver_id,
            "sha256": hashlib.sha256(
                (json.dumps(capture.to_dict(), sort_keys=True) + "\n").encode()
            ).hexdigest(),
        }
        for index, capture in enumerate(captures, start=1)
    ]
    bundle = {
        "bundle_schema_version": 1,
        "captures": [capture.to_dict() for capture in captures],
        "driver_versions": {
            driver_id: get_driver(driver_id).info.version
            for driver_id in sorted({capture.driver_id for capture in captures})
        },
        "fingerprint": build_fingerprint(captures).to_dict(),
        "fixture_manifest": manifest,
        "provenance_notes": provenance_notes,
        "qsidentify_version": __version__,
        "report": evidence_report(captures),
    }
    payload = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=output.parent, prefix=f".{output.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return bundle


def inspect_bundle(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise EvidenceError("Evidence bundle must be a JSON object.")
    captures = raw.get("captures", [])
    return {
        "bundle_schema_version": raw.get("bundle_schema_version"),
        "capture_count": len(captures) if isinstance(captures, list) else 0,
        "fingerprint_id": (raw.get("fingerprint") or {}).get("fingerprint_id"),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def validate_bundle(path: Path) -> tuple[bool, tuple[str, ...]]:
    errors: list[str] = []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, (str(exc),)
    if not isinstance(raw, dict) or raw.get("bundle_schema_version") != 1:
        errors.append("unsupported or malformed bundle schema")
    captures = raw.get("captures") if isinstance(raw, dict) else None
    if not isinstance(captures, list) or not captures:
        errors.append("bundle must contain sanitized captures")
    else:
        forbidden = {"hostname", "username", "home_directory", "usb_serial_number"}
        serialized = json.dumps(captures, sort_keys=True).lower()
        for field in forbidden:
            if f'"{field}"' in serialized:
                errors.append(f"forbidden host field: {field}")
        for capture in captures:
            metadata = capture.get("capture_metadata") if isinstance(capture, dict) else None
            if not isinstance(metadata, dict) or metadata.get("sanitized") is not True:
                errors.append("capture lacks sanitization metadata")
            if not isinstance(capture, dict) or capture.get("schema_version") not in {1, 2, 3}:
                errors.append("capture has unsupported schema")
                continue
            try:
                raw_response = bytes.fromhex(str(capture["raw_response_hex"]))
                chunks = capture["read_chunks"]
                combined = b"".join(bytes.fromhex(str(chunk["data_hex"])) for chunk in chunks)
            except (KeyError, TypeError, ValueError):
                errors.append("capture contains malformed hexadecimal or chunks")
                continue
            if combined != raw_response:
                errors.append("capture chunk concatenation does not match raw response")
            operation = capture.get("operation")
            transmitted = capture.get("transmit_performed")
            if operation == "monitor" and transmitted is not False:
                errors.append("monitor capture claims transmission")
            if operation == "probe" and transmitted is not True:
                errors.append("probe capture does not declare transmission")
            driver_id = capture.get("driver_id")
            try:
                get_driver(str(driver_id))
            except KeyError:
                errors.append(f"unknown capture driver: {driver_id}")
    return not errors, tuple(sorted(set(errors)))


__all__ = [
    "CommandDescriptor",
    "DISCRIMINATOR_CATALOG_SCHEMA_VERSION",
    "ElectronicFingerprint",
    "EvidenceError",
    "FINGERPRINT_SCHEMA_VERSION",
    "ProbeDefinition",
    "ScopedConfidence",
    "StabilityAnalysis",
    "analyze_stability",
    "build_fingerprint",
    "compare_evidence",
    "evidence_report",
    "load_command_inventory",
    "load_discriminators",
    "load_probe_definitions",
    "export_bundle",
    "inspect_bundle",
    "report_paths",
    "validate_bundle",
]
