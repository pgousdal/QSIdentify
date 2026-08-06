"""Immutable review records and blind review support.

A review is a frozen record that is appended to the governance ledger. Blind
review produces anonymous evidence views that never leak contributor, hostname,
USB serial or filesystem metadata unless explicitly shared.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

from .ledger import _with_digest, append_audit
from .models import (
    ConfidenceLevel,
    GovernanceError,
    GovernanceLedger,
    ReviewDecision,
    ReviewRecord,
    ReviewType,
    sha256_digest,
    utc,
)

BLIND_STRIP_KEYS = frozenset(
    {
        "hostname",
        "host_name",
        "username",
        "user_name",
        "home_directory",
        "usb_serial_number",
        "usb_serial",
        "contributor",
        "contributor_id",
        "filesystem",
        "device_path",
        "port_device",
    }
)

BLIND_STRIP_PREFIXES = ("/home/", "C:\\Users\\", "/dev/", "file://")


def strip_blind_metadata(value: object) -> Any:
    """Recursively remove contributor and host metadata from a review view."""
    if isinstance(value, dict):
        return {
            key: strip_blind_metadata(child)
            for key, child in value.items()
            if str(key).lower() not in BLIND_STRIP_KEYS
        }
    if isinstance(value, list):
        return [strip_blind_metadata(child) for child in value]
    if isinstance(value, str):
        for prefix in BLIND_STRIP_PREFIXES:
            if value.startswith(prefix):
                return "<redacted>"
    return value


def blind_review_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return an anonymized, review-only view of an evidence bundle."""
    return cast(dict[str, Any], strip_blind_metadata(bundle))


def create_review(
    ledger: GovernanceLedger,
    *,
    reviewer_id: str,
    review_type: ReviewType,
    decision: ReviewDecision,
    rationale: str,
    subject_id: str,
    supporting_evidence: tuple[str, ...] = (),
    contradicting_evidence: tuple[str, ...] = (),
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
    references: tuple[str, ...] = (),
    blind: bool = False,
    timestamp: str | None = None,
) -> tuple[GovernanceLedger, ReviewRecord]:
    """Record one immutable review. Returns the new ledger and the review."""
    if not reviewer_id.strip():
        raise GovernanceError("reviewer_id_required")
    if not rationale.strip():
        raise GovernanceError("rationale_required")
    now = utc(timestamp)
    identity = sha256_digest(
        {
            "confidence": confidence.value,
            "contradicting_evidence": sorted(set(contradicting_evidence)),
            "decision": decision.value,
            "review_type": review_type.value,
            "reviewer_id": reviewer_id,
            "subject_id": subject_id,
            "supporting_evidence": sorted(set(supporting_evidence)),
            "timestamp": now,
        }
    )
    review = ReviewRecord(
        review_id="review:sha256:" + identity,
        subject_id=subject_id,
        reviewer_id=reviewer_id,
        timestamp=now,
        review_type=review_type,
        decision=decision,
        rationale=rationale,
        supporting_evidence=tuple(sorted(set(supporting_evidence))),
        contradicting_evidence=tuple(sorted(set(contradicting_evidence))),
        confidence=confidence,
        references=tuple(sorted(set(references))),
        blind=blind,
    )
    updated, audit = append_audit(
        ledger,
        event_type="review",
        subject_id=subject_id,
        actor=reviewer_id,
        detail=f"{decision.value} ({review_type.value}): {rationale}",
        timestamp=now,
    )
    updated = replace(
        updated,
        updated_utc=now,
        reviews=tuple(sorted((*updated.reviews, review), key=lambda item: item.review_id)),
    )
    return _with_digest(updated), review


def find_review(ledger: GovernanceLedger, review_id: str) -> ReviewRecord | None:
    return next((item for item in ledger.reviews if item.review_id == review_id), None)


def reviews_for_subject(ledger: GovernanceLedger, subject_id: str) -> tuple[ReviewRecord, ...]:
    return tuple(item for item in ledger.reviews if item.subject_id == subject_id)


def review_to_json(review: ReviewRecord) -> dict[str, Any]:
    return review.to_dict()


__all__ = [
    "BLIND_STRIP_KEYS",
    "blind_review_bundle",
    "create_review",
    "find_review",
    "review_to_json",
    "reviews_for_subject",
    "strip_blind_metadata",
]
