from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from qsidentify.models import Capture, MessageType, TransportClassification

from .catalog import (
    FirmwareCatalog,
    FirmwareEntry,
    HardwareRecord,
    load_firmware_catalog,
    load_hardware_records,
)


class EvidenceSource(StrEnum):
    PROTOCOL = "protocol"
    FIRMWARE_STRING = "firmware-string"
    BOOTLOADER = "bootloader"
    LABEL = "label"
    USER_INPUT = "user-input"
    DATABASE = "database"


class ScopeConfidence(StrEnum):
    CONFIRMED = "confirmed"
    STRONG = "strong"
    TENTATIVE = "tentative"
    USER_SUPPLIED = "user-supplied"
    DATABASE_INFERENCE = "database-inference"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class Compatibility(StrEnum):
    COMPATIBLE_CONFIRMED = "compatible-confirmed"
    COMPATIBLE_DECLARED = "compatible-by-declared-hardware"
    POTENTIALLY_COMPATIBLE = "potentially-compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting-evidence"


@dataclass(frozen=True, slots=True)
class AdvisoryEvidence:
    source: EvidenceSource
    value: str
    confidence: ScopeConfidence
    explanation: str


@dataclass(frozen=True, slots=True)
class ConfidenceScopes:
    serial_transport: ScopeConfidence
    protocol_family: ScopeConfidence
    firmware_version: ScopeConfidence
    radio_model: ScopeConfidence
    hardware_revision: ScopeConfidence
    mcu_family: ScopeConfidence
    firmware_compatibility: ScopeConfidence


@dataclass(frozen=True, slots=True)
class HardwareInput:
    model: str | None = None
    hardware_revision: str | None = None
    mcu: str | None = None
    pcb_marking: str | None = None


@dataclass(frozen=True, slots=True)
class AdvisoryEntry:
    catalog_id: str
    name: str
    project: str
    compatibility: Compatibility
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FirmwareAdvisory:
    catalog_version: str
    observed_firmware: str | None
    protocol_family: str | None
    marketed_model: str | None
    hardware_revision: str | None
    hardware_revision_id: str | None
    mcu: str | None
    evidence: tuple[AdvisoryEvidence, ...]
    confidence: ConfidenceScopes
    entries: tuple[AdvisoryEntry, ...]
    warnings: tuple[str, ...]
    conflicting: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_version": self.catalog_version,
            "confidence": {
                "firmware_compatibility": self.confidence.firmware_compatibility.value,
                "firmware_version": self.confidence.firmware_version.value,
                "hardware_revision": self.confidence.hardware_revision.value,
                "mcu_family": self.confidence.mcu_family.value,
                "protocol_family": self.confidence.protocol_family.value,
                "radio_model": self.confidence.radio_model.value,
                "serial_transport": self.confidence.serial_transport.value,
            },
            "conflicting": self.conflicting,
            "entries": [
                {
                    "catalog_id": item.catalog_id,
                    "compatibility": item.compatibility.value,
                    "name": item.name,
                    "project": item.project,
                    "reasons": list(item.reasons),
                }
                for item in self.entries
            ],
            "evidence": [
                {
                    "confidence": item.confidence.value,
                    "explanation": item.explanation,
                    "source": item.source.value,
                    "value": item.value,
                }
                for item in self.evidence
            ],
            "hardware_revision": self.hardware_revision,
            "hardware_revision_id": self.hardware_revision_id,
            "marketed_model": self.marketed_model,
            "mcu": self.mcu,
            "observed_firmware": self.observed_firmware,
            "protocol_family": self.protocol_family,
            "warnings": list(self.warnings),
        }


def _normalize(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _record_for_revision(
    value: str | None, records: tuple[HardwareRecord, ...]
) -> HardwareRecord | None:
    if value is None:
        return None
    normalized = _normalize(value)
    return next(
        (
            record
            for record in records
            if normalized
            in {
                _normalize(record.id),
                _normalize(record.revision),
                *(_normalize(marking) for marking in record.pcb_markings),
            }
        ),
        None,
    )


def _record_for_pcb(
    value: str | None, records: tuple[HardwareRecord, ...]
) -> HardwareRecord | None:
    if value is None:
        return None
    normalized = _normalize(value)
    matches = [
        record
        for record in records
        if normalized in {_normalize(marking) for marking in record.pcb_markings}
    ]
    return matches[0] if len(matches) == 1 else None


def _entry_decision(
    entry: FirmwareEntry,
    *,
    revision: HardwareRecord | None,
    mcu: str | None,
    declared_hardware: bool,
    conflicting: bool,
) -> AdvisoryEntry:
    if conflicting:
        return AdvisoryEntry(
            entry.id,
            entry.name,
            entry.project,
            Compatibility.CONFLICTING,
            (
                "User-supplied revision and MCU evidence conflict; "
                "no compatibility conclusion was made.",
            ),
        )
    revision_id = revision.id if revision else None
    if revision is not None and (
        revision.id in entry.unsupported_revisions or revision.mcu not in entry.supported_mcus
    ):
        return AdvisoryEntry(
            entry.id,
            entry.name,
            entry.project,
            Compatibility.INCOMPATIBLE,
            (f"Catalog metadata does not support {revision.revision} / {revision.mcu} hardware.",),
        )
    if mcu is not None and mcu not in entry.supported_mcus:
        return AdvisoryEntry(
            entry.id,
            entry.name,
            entry.project,
            Compatibility.INCOMPATIBLE,
            (f"Catalog metadata does not support the declared {mcu} MCU.",),
        )
    if declared_hardware and (
        revision_id in entry.supported_revisions or mcu in entry.supported_mcus
    ):
        basis = revision.revision if revision else mcu
        return AdvisoryEntry(
            entry.id,
            entry.name,
            entry.project,
            Compatibility.COMPATIBLE_DECLARED,
            (f"The catalog supports {basis}, based on user-supplied hardware information.",),
        )
    requirements = " / ".join(entry.supported_mcus)
    return AdvisoryEntry(
        entry.id,
        entry.name,
        entry.project,
        Compatibility.UNKNOWN,
        (f"Requires {requirements} hardware; the exact hardware revision was not established.",),
    )


def build_advisory(
    capture: Capture,
    hardware_input: HardwareInput | None = None,
    *,
    catalog: FirmwareCatalog | None = None,
    hardware_records: tuple[HardwareRecord, ...] | None = None,
) -> FirmwareAdvisory:
    hardware_input = hardware_input or HardwareInput()
    catalog = catalog or load_firmware_catalog()
    records = hardware_records or load_hardware_records()
    evidence: list[AdvisoryEvidence] = []
    report = capture.report
    framed = capture.stream_classification in {
        TransportClassification.FRAMED_RESPONSE,
        TransportClassification.ECHO_FOLLOWED_BY_RESPONSE,
    }
    transport_confidence = ScopeConfidence.CONFIRMED if framed else ScopeConfidence.UNKNOWN
    protocol_family = None
    protocol_confidence = ScopeConfidence.UNKNOWN
    if report.detected_protocol and report.detected_protocol.startswith("Quansheng framed"):
        protocol_family = "Quansheng UV-K5 protocol"
        protocol_confidence = ScopeConfidence.CONFIRMED
        evidence.append(
            AdvisoryEvidence(
                EvidenceSource.PROTOCOL,
                report.detected_protocol,
                ScopeConfidence.CONFIRMED,
                "A checksum-valid decoded Quansheng frame was observed.",
            )
        )
    firmware_confidence = ScopeConfidence.UNKNOWN
    if report.reported_version and report.message_type is MessageType.FIRMWARE_IDENTIFICATION:
        firmware_confidence = ScopeConfidence.CONFIRMED
        evidence.append(
            AdvisoryEvidence(
                EvidenceSource.FIRMWARE_STRING,
                report.reported_version,
                ScopeConfidence.CONFIRMED,
                "The string was decoded from a valid firmware-identification response; "
                "it does not identify the hardware revision.",
            )
        )
    model_confidence = ScopeConfidence.UNKNOWN
    if hardware_input.model:
        model_confidence = ScopeConfidence.USER_SUPPLIED
        evidence.append(
            AdvisoryEvidence(
                EvidenceSource.USER_INPUT,
                hardware_input.model,
                ScopeConfidence.USER_SUPPLIED,
                "The marketed model was supplied by the user and was not verified electronically.",
            )
        )
    supplied_revision = _record_for_revision(hardware_input.hardware_revision, records)
    pcb_revision = _record_for_pcb(hardware_input.pcb_marking, records)
    revision = supplied_revision or pcb_revision
    revision_confidence = ScopeConfidence.UNKNOWN
    if hardware_input.hardware_revision:
        revision_confidence = ScopeConfidence.USER_SUPPLIED
        evidence.append(
            AdvisoryEvidence(
                EvidenceSource.USER_INPUT,
                hardware_input.hardware_revision,
                ScopeConfidence.USER_SUPPLIED,
                "The hardware revision was supplied by the user and was not "
                "verified electronically.",
            )
        )
    if hardware_input.pcb_marking:
        evidence.append(
            AdvisoryEvidence(
                EvidenceSource.LABEL,
                hardware_input.pcb_marking,
                ScopeConfidence.USER_SUPPLIED,
                "The PCB marking was transcribed by the user and was not inspected by QSIdentify.",
            )
        )
        revision_confidence = (
            ScopeConfidence.DATABASE_INFERENCE if pcb_revision else revision_confidence
        )
    supplied_mcu = hardware_input.mcu.upper() if hardware_input.mcu else None
    inferred_mcu = revision.mcu if revision else None
    resolved_mcu = supplied_mcu or inferred_mcu
    mcu_confidence = ScopeConfidence.UNKNOWN
    if supplied_mcu:
        mcu_confidence = ScopeConfidence.USER_SUPPLIED
        evidence.append(
            AdvisoryEvidence(
                EvidenceSource.USER_INPUT,
                supplied_mcu,
                ScopeConfidence.USER_SUPPLIED,
                "The MCU identifier was supplied by the user and was not verified electronically.",
            )
        )
    elif inferred_mcu:
        mcu_confidence = ScopeConfidence.DATABASE_INFERENCE
        evidence.append(
            AdvisoryEvidence(
                EvidenceSource.DATABASE,
                inferred_mcu,
                ScopeConfidence.DATABASE_INFERENCE,
                "The MCU was inferred from a canonical record selected by "
                "user-supplied revision evidence.",
            )
        )
    conflict_reasons: list[str] = []
    if supplied_revision and pcb_revision and supplied_revision.id != pcb_revision.id:
        conflict_reasons.append(
            "The supplied hardware revision and PCB marking identify different records."
        )
    if revision and supplied_mcu and revision.mcu != supplied_mcu:
        conflict_reasons.append(
            f"The supplied {revision.revision} revision maps to {revision.mcu}, not {supplied_mcu}."
        )
    conflicting = bool(conflict_reasons)
    if conflicting:
        revision_confidence = ScopeConfidence.CONFLICTING
        mcu_confidence = ScopeConfidence.CONFLICTING
    declared = bool(
        hardware_input.hardware_revision or hardware_input.mcu or hardware_input.pcb_marking
    )
    entries = tuple(
        _entry_decision(
            entry,
            revision=revision,
            mcu=resolved_mcu,
            declared_hardware=declared,
            conflicting=conflicting,
        )
        for entry in catalog.entries
    )
    if conflicting:
        compatibility_confidence = ScopeConfidence.CONFLICTING
    elif any(item.compatibility is Compatibility.COMPATIBLE_DECLARED for item in entries):
        compatibility_confidence = ScopeConfidence.USER_SUPPLIED
    else:
        compatibility_confidence = ScopeConfidence.UNKNOWN
    warnings = conflict_reasons
    warnings.append(
        "No firmware should be flashed based on a firmware string or marketed model alone."
    )
    if declared and not conflicting:
        warnings.append(
            "Compatibility is based on user-supplied hardware information and was not "
            "verified electronically by QSIdentify."
        )
    warnings.append("Catalog metadata is curated, offline advisory data and may become stale.")
    return FirmwareAdvisory(
        catalog.catalog_version,
        report.reported_version,
        protocol_family,
        hardware_input.model,
        revision.revision if revision else hardware_input.hardware_revision,
        revision.id if revision else None,
        resolved_mcu,
        tuple(evidence),
        ConfidenceScopes(
            transport_confidence,
            protocol_confidence,
            firmware_confidence,
            model_confidence,
            revision_confidence,
            mcu_confidence,
            compatibility_confidence,
        ),
        entries,
        tuple(warnings),
        conflicting,
    )


__all__ = [
    "AdvisoryEntry",
    "AdvisoryEvidence",
    "Compatibility",
    "ConfidenceScopes",
    "EvidenceSource",
    "FirmwareAdvisory",
    "HardwareInput",
    "ScopeConfidence",
    "build_advisory",
]
