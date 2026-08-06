"""Immutable domain models and deterministic serialization helpers for the M2.0
trusted evidence governance layer.

All models are frozen dataclasses. Every mutation produces a brand new
``GovernanceLedger``; past records are never edited.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class GovernanceError(ValueError):
    """Base error for trusted evidence governance operations."""


class EvidenceStage(StrEnum):
    """Immutable evidence stages in dependency order."""

    OBSERVED = "observed"
    SANITIZED = "sanitized"
    IMPORTED = "imported"
    REVIEWED = "reviewed"
    CORRELATED = "correlated"
    CANDIDATE = "candidate"
    APPROVED = "approved"
    PUBLISHED = "published"


STAGE_ORDER: tuple[EvidenceStage, ...] = tuple(EvidenceStage)


class ReviewDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_MORE_EVIDENCE = "request-more-evidence"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class ReviewType(StrEnum):
    EVIDENCE = "evidence"
    CANDIDATE = "candidate"
    PROPOSAL = "proposal"
    PUBLICATION = "publication"


class ProposalStatus(StrEnum):
    DRAFTED = "drafted"
    UNDER_REVIEW = "under-review"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    PUBLISHED = "published"


class ConfidenceLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    """Configurable project thresholds. These are engineering policy, not
    scientific proof. Thresholds are the number of independent radios required
    for each downstream capability."""

    stability_device_count: int = 1
    comparison_device_count: int = 2
    correlation_device_count: int = 3
    review_device_count: int = 5
    proposal_device_count: int = 10

    def to_dict(self) -> dict[str, int]:
        return {
            "comparison_device_count": self.comparison_device_count,
            "correlation_device_count": self.correlation_device_count,
            "proposal_device_count": self.proposal_device_count,
            "review_device_count": self.review_device_count,
            "stability_device_count": self.stability_device_count,
        }


@dataclass(frozen=True, slots=True)
class ConfidenceProfile:
    """Structured confidence. Fields are intentionally never combined into a
    single aggregate automatically."""

    transport: ConfidenceLevel = ConfidenceLevel.NONE
    protocol: ConfidenceLevel = ConfidenceLevel.NONE
    firmware: ConfidenceLevel = ConfidenceLevel.NONE
    fingerprint: ConfidenceLevel = ConfidenceLevel.NONE
    statistical: ConfidenceLevel = ConfidenceLevel.NONE
    review: ConfidenceLevel = ConfidenceLevel.NONE
    catalog: ConfidenceLevel = ConfidenceLevel.NONE

    def to_dict(self) -> dict[str, str]:
        return {
            "transport": self.transport.value,
            "protocol": self.protocol.value,
            "firmware": self.firmware.value,
            "fingerprint": self.fingerprint.value,
            "statistical": self.statistical.value,
            "review": self.review.value,
            "catalog": self.catalog.value,
        }


@dataclass(frozen=True, slots=True)
class LifecycleTransition:
    """One immutable evidence promotion. History is never rewritten; correcting
    an earlier step always appends a new transition."""

    sequence: int
    subject_id: str
    from_stage: EvidenceStage | None
    to_stage: EvidenceStage
    actor: str
    reviewer_id: str | None
    timestamp: str
    rationale: str
    evidence_ids: tuple[str, ...]
    audit_event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "audit_event_id": self.audit_event_id,
            "evidence_ids": list(self.evidence_ids),
            "from_stage": self.from_stage.value if self.from_stage else None,
            "rationale": self.rationale,
            "reviewer_id": self.reviewer_id,
            "sequence": self.sequence,
            "subject_id": self.subject_id,
            "timestamp": self.timestamp,
            "to_stage": self.to_stage.value,
        }


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Append-only, chain-linked audit event."""

    sequence: int
    timestamp: str
    event_type: str
    subject_id: str
    actor: str
    detail: str
    previous_digest: str
    event_digest: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "actor": self.actor,
            "detail": self.detail,
            "event_digest": self.event_digest,
            "event_type": self.event_type,
            "previous_digest": self.previous_digest,
            "sequence": self.sequence,
            "subject_id": self.subject_id,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class ReviewRecord:
    review_id: str
    subject_id: str
    reviewer_id: str
    timestamp: str
    review_type: ReviewType
    decision: ReviewDecision
    rationale: str
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    confidence: ConfidenceLevel
    references: tuple[str, ...]
    blind: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "blind": self.blind,
            "confidence": self.confidence.value,
            "contradicting_evidence": list(self.contradicting_evidence),
            "decision": self.decision.value,
            "rationale": self.rationale,
            "references": list(self.references),
            "review_id": self.review_id,
            "review_type": self.review_type.value,
            "reviewer_id": self.reviewer_id,
            "subject_id": self.subject_id,
            "supporting_evidence": list(self.supporting_evidence),
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class ProposedCatalogEntry:
    """A proposed, not yet approved, catalog record. Kept as ordered key/value
    pairs for deterministic serialization."""

    entry_id: str
    catalog_kind: str
    fields: tuple[tuple[str, str], ...]
    evidence_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_kind": self.catalog_kind,
            "entry_id": self.entry_id,
            "evidence_ids": list(self.evidence_ids),
            "fields": [list(item) for item in self.fields],
        }


@dataclass(frozen=True, slots=True)
class CatalogProposal:
    """A catalog proposal. Never mutates production catalogs by itself."""

    proposal_id: str
    status: ProposalStatus
    rationale: str
    entries: tuple[ProposedCatalogEntry, ...]
    supporting_bundle_ids: tuple[str, ...]
    supporting_device_ids: tuple[str, ...]
    reviewer_ids: tuple[str, ...]
    review_ids: tuple[str, ...]
    thresholds_satisfied: tuple[str, ...]
    created_utc: str
    updated_utc: str
    publication_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_utc": self.created_utc,
            "entries": [item.to_dict() for item in self.entries],
            "proposal_id": self.proposal_id,
            "publication_id": self.publication_id,
            "rationale": self.rationale,
            "review_ids": list(self.review_ids),
            "reviewer_ids": list(self.reviewer_ids),
            "status": self.status.value,
            "supporting_bundle_ids": list(self.supporting_bundle_ids),
            "supporting_device_ids": list(self.supporting_device_ids),
            "thresholds_satisfied": list(self.thresholds_satisfied),
            "updated_utc": self.updated_utc,
        }


@dataclass(frozen=True, slots=True)
class PublicationRecord:
    """Record of a built publication package and its regression certification."""

    publication_id: str
    proposal_id: str
    schema_version: int
    catalog_entry_ids: tuple[str, ...]
    review_ids: tuple[str, ...]
    bundle_ids: tuple[str, ...]
    device_ids: tuple[str, ...]
    reviewer_ids: tuple[str, ...]
    thresholds_satisfied: tuple[str, ...]
    built_utc: str
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_ids": list(self.bundle_ids),
            "built_utc": self.built_utc,
            "catalog_entry_ids": list(self.catalog_entry_ids),
            "device_ids": list(self.device_ids),
            "proposal_id": self.proposal_id,
            "publication_id": self.publication_id,
            "review_ids": list(self.review_ids),
            "reviewer_ids": list(self.reviewer_ids),
            "schema_version": self.schema_version,
            "sha256": self.sha256,
            "thresholds_satisfied": list(self.thresholds_satisfied),
        }


@dataclass(frozen=True, slots=True)
class GovernanceLedger:
    """Immutable, append-only governance ledger. Every mutation returns a new
    instance with a chained audit event and a new ledger digest."""

    schema_version: int
    ledger_id: str
    created_utc: str
    updated_utc: str
    qsidentify_version: str
    policy: EvidencePolicy
    reviews: tuple[ReviewRecord, ...]
    proposals: tuple[CatalogProposal, ...]
    publications: tuple[PublicationRecord, ...]
    transitions: tuple[LifecycleTransition, ...]
    audit_events: tuple[AuditEvent, ...]
    ledger_digest: str

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "audit_events": [item.to_dict() for item in self.audit_events],
            "created_utc": self.created_utc,
            "ledger_id": self.ledger_id,
            "policy": self.policy.to_dict(),
            "proposals": [item.to_dict() for item in self.proposals],
            "publications": [item.to_dict() for item in self.publications],
            "qsidentify_version": self.qsidentify_version,
            "reviews": [item.to_dict() for item in self.reviews],
            "schema_version": self.schema_version,
            "transitions": [item.to_dict() for item in self.transitions],
            "updated_utc": self.updated_utc,
        }
        if include_digest:
            payload["ledger_digest"] = self.ledger_digest
        return payload


def authoritative_stage(ledger: GovernanceLedger, subject_id: str) -> EvidenceStage | None:
    """Return the latest recorded stage for a subject, or None if unknown."""
    latest: EvidenceStage | None = None
    for transition in ledger.transitions:
        if transition.subject_id == subject_id:
            latest = transition.to_stage
    return latest


def current_stage(ledger: GovernanceLedger, subject_id: str) -> EvidenceStage | None:
    return authoritative_stage(ledger, subject_id)


def canonical(value: object, *, pretty: bool = False) -> bytes:
    """Deterministic JSON encoding used for all identities and digests."""
    if pretty:
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_digest(value: object) -> str:
    """Return a sha256 hex digest (prefix included by callers)."""
    return hashlib.sha256(canonical(value)).hexdigest()


def utc(value: str | None) -> str:
    if value is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise GovernanceError("Governance timestamps must be ISO-8601.") from exc
    if parsed.tzinfo is None:
        raise GovernanceError("Governance timestamps must include a UTC offset.")
    return value


__all__ = [
    "AuditEvent",
    "CatalogProposal",
    "ConfidenceLevel",
    "ConfidenceProfile",
    "EvidencePolicy",
    "EvidenceStage",
    "GovernanceLedger",
    "LifecycleTransition",
    "ProposedCatalogEntry",
    "ProposalStatus",
    "PublicationRecord",
    "ReviewDecision",
    "ReviewRecord",
    "ReviewType",
    "STAGE_ORDER",
    "authoritative_stage",
    "canonical",
    "sha256_digest",
    "utc",
]
