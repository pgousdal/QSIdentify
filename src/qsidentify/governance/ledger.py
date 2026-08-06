"""Append-only governance ledger: lifecycle transitions, audit chain, and
deterministic JSON persistence. Nothing here rewrites history."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, NoReturn

from .. import __version__
from ..evidence_registry import EvidenceRegistry
from .models import (
    STAGE_ORDER,
    AuditEvent,
    CatalogProposal,
    ConfidenceLevel,
    EvidencePolicy,
    EvidenceStage,
    GovernanceError,
    GovernanceLedger,
    LifecycleTransition,
    ProposalStatus,
    ProposedCatalogEntry,
    PublicationRecord,
    ReviewDecision,
    ReviewRecord,
    ReviewType,
    authoritative_stage,
    canonical,
    sha256_digest,
    utc,
)
from .policy import evaluate_thresholds, stage_capability

GOVERNANCE_SCHEMA_VERSION = 1

HUMAN_GATED_STAGES = {
    EvidenceStage.REVIEWED,
    EvidenceStage.CANDIDATE,
    EvidenceStage.APPROVED,
    EvidenceStage.PUBLISHED,
}

NON_HUMAN_ACTORS = {"tool", "system", ""}


class GovernanceSchemaError(GovernanceError):
    """Raised for malformed or unsupported governance ledgers."""


@dataclass(frozen=True, slots=True)
class GovernanceValidation:
    valid: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "errors": list(self.errors),
            "valid": self.valid,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class TransitionResult:
    ledger: GovernanceLedger
    transition: LifecycleTransition
    audit_event: AuditEvent


def create_governance(
    *,
    timestamp: str | None = None,
    policy: EvidencePolicy | None = None,
) -> GovernanceLedger:
    if policy is None:
        policy = EvidencePolicy()
    created = utc(timestamp)
    identity = sha256_digest({"created_utc": created, "policy": policy.to_dict()})
    return _with_digest(
        GovernanceLedger(
            schema_version=GOVERNANCE_SCHEMA_VERSION,
            ledger_id=f"ledger:sha256:{identity}",
            created_utc=created,
            updated_utc=created,
            qsidentify_version=__version__,
            policy=policy,
            reviews=(),
            proposals=(),
            publications=(),
            transitions=(),
            audit_events=(),
            ledger_digest="",
        )
    )


def _fail(message: str) -> NoReturn:
    raise GovernanceSchemaError(message)


def _policy_from_dict(raw: object) -> EvidencePolicy:
    if not isinstance(raw, dict):
        _fail("policy must be an object")
    try:
        return EvidencePolicy(
            stability_device_count=raw["stability_device_count"],
            comparison_device_count=raw["comparison_device_count"],
            correlation_device_count=raw["correlation_device_count"],
            review_device_count=raw["review_device_count"],
            proposal_device_count=raw["proposal_device_count"],
        )
    except KeyError as exc:
        _fail(f"policy missing field: {exc}")


def _review_from_dict(raw: object) -> ReviewRecord:
    if not isinstance(raw, dict):
        _fail("review must be an object")
    try:
        return ReviewRecord(
            review_id=raw["review_id"],
            subject_id=raw["subject_id"],
            reviewer_id=raw["reviewer_id"],
            timestamp=raw["timestamp"],
            review_type=ReviewType(raw["review_type"]),
            decision=ReviewDecision(raw["decision"]),
            rationale=raw["rationale"],
            supporting_evidence=tuple(raw["supporting_evidence"]),
            contradicting_evidence=tuple(raw["contradicting_evidence"]),
            confidence=ConfidenceLevel(raw["confidence"]),
            references=tuple(raw["references"]),
            blind=bool(raw["blind"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail(f"malformed review: {exc}")


def _proposal_from_dict(raw: object) -> CatalogProposal:
    if not isinstance(raw, dict):
        _fail("proposal must be an object")
    try:
        entries = tuple(
            ProposedCatalogEntry(
                entry_id=item["entry_id"],
                catalog_kind=item["catalog_kind"],
                fields=tuple(tuple(field) for field in item["fields"]),
                evidence_ids=tuple(item["evidence_ids"]),
            )
            for item in raw["entries"]
        )
        return CatalogProposal(
            proposal_id=raw["proposal_id"],
            status=ProposalStatus(raw["status"]),
            rationale=raw["rationale"],
            entries=entries,
            supporting_bundle_ids=tuple(raw["supporting_bundle_ids"]),
            supporting_device_ids=tuple(raw["supporting_device_ids"]),
            reviewer_ids=tuple(raw["reviewer_ids"]),
            review_ids=tuple(raw["review_ids"]),
            thresholds_satisfied=tuple(raw["thresholds_satisfied"]),
            created_utc=raw["created_utc"],
            updated_utc=raw["updated_utc"],
            publication_id=raw.get("publication_id"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail(f"malformed proposal: {exc}")


def _publication_from_dict(raw: object) -> PublicationRecord:
    if not isinstance(raw, dict):
        _fail("publication must be an object")
    try:
        return PublicationRecord(
            publication_id=raw["publication_id"],
            proposal_id=raw["proposal_id"],
            schema_version=raw["schema_version"],
            catalog_entry_ids=tuple(raw["catalog_entry_ids"]),
            review_ids=tuple(raw["review_ids"]),
            bundle_ids=tuple(raw["bundle_ids"]),
            device_ids=tuple(raw["device_ids"]),
            reviewer_ids=tuple(raw["reviewer_ids"]),
            thresholds_satisfied=tuple(raw["thresholds_satisfied"]),
            built_utc=raw["built_utc"],
            sha256=raw["sha256"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail(f"malformed publication: {exc}")


def _transition_from_dict(raw: object) -> LifecycleTransition:
    if not isinstance(raw, dict):
        _fail("transition must be an object")
    try:
        return LifecycleTransition(
            sequence=raw["sequence"],
            subject_id=raw["subject_id"],
            from_stage=EvidenceStage(raw["from_stage"]) if raw["from_stage"] else None,
            to_stage=EvidenceStage(raw["to_stage"]),
            actor=raw["actor"],
            reviewer_id=raw.get("reviewer_id"),
            timestamp=raw["timestamp"],
            rationale=raw["rationale"],
            evidence_ids=tuple(raw["evidence_ids"]),
            audit_event_id=raw.get("audit_event_id"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail(f"malformed transition: {exc}")


def _audit_from_dict(raw: object) -> AuditEvent:
    if not isinstance(raw, dict):
        _fail("audit event must be an object")
    try:
        return AuditEvent(
            sequence=raw["sequence"],
            timestamp=raw["timestamp"],
            event_type=raw["event_type"],
            subject_id=raw["subject_id"],
            actor=raw["actor"],
            detail=raw["detail"],
            previous_digest=raw["previous_digest"],
            event_digest=raw["event_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail(f"malformed audit event: {exc}")


def governance_from_dict(raw: object) -> GovernanceLedger:
    if not isinstance(raw, dict):
        _fail("Governance ledger must be a JSON object.")
    if raw.get("schema_version") != GOVERNANCE_SCHEMA_VERSION:
        _fail(f"Unsupported governance schema: {raw.get('schema_version')}")
    try:
        ledger = GovernanceLedger(
            schema_version=raw["schema_version"],
            ledger_id=raw["ledger_id"],
            created_utc=raw["created_utc"],
            updated_utc=raw["updated_utc"],
            qsidentify_version=raw["qsidentify_version"],
            policy=_policy_from_dict(raw["policy"]),
            reviews=tuple(_review_from_dict(item) for item in raw["reviews"]),
            proposals=tuple(_proposal_from_dict(item) for item in raw["proposals"]),
            publications=tuple(_publication_from_dict(item) for item in raw["publications"]),
            transitions=tuple(_transition_from_dict(item) for item in raw["transitions"]),
            audit_events=tuple(_audit_from_dict(item) for item in raw["audit_events"]),
            ledger_digest=raw["ledger_digest"],
        )
    except KeyError as exc:
        _fail(f"Malformed governance ledger: missing {exc}")
    return ledger


def _with_digest(ledger: GovernanceLedger) -> GovernanceLedger:
    digest = "sha256:" + sha256_digest(ledger.to_dict(include_digest=False))
    return replace(ledger, ledger_digest=digest)


def load_governance(path: Path) -> GovernanceLedger:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"Unable to load governance ledger: {exc}") from exc
    ledger = governance_from_dict(raw)
    validation = validate_governance(ledger)
    if not validation.valid:
        raise GovernanceSchemaError("; ".join(validation.errors))
    return ledger


def write_governance(path: Path, ledger: GovernanceLedger) -> None:
    validated = _with_digest(ledger)
    result = validate_governance(validated)
    if not result.valid:
        raise GovernanceSchemaError("; ".join(result.errors))
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical(validated.to_dict(), pretty=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _event_digest(event: AuditEvent) -> str:
    return sha256_digest(
        {
            "actor": event.actor,
            "detail": event.detail,
            "event_type": event.event_type,
            "previous_digest": event.previous_digest,
            "sequence": event.sequence,
            "subject_id": event.subject_id,
            "timestamp": event.timestamp,
        }
    )


def append_audit(
    ledger: GovernanceLedger,
    *,
    event_type: str,
    subject_id: str,
    actor: str,
    detail: str,
    timestamp: str | None = None,
) -> tuple[GovernanceLedger, AuditEvent]:
    """Append one chained audit event. Returns the new ledger and the event."""
    now = utc(timestamp)
    previous = ledger.audit_events[-1].event_digest if ledger.audit_events else ""
    sequence = len(ledger.audit_events) + 1
    event = AuditEvent(
        sequence=sequence,
        timestamp=now,
        event_type=event_type,
        subject_id=subject_id,
        actor=actor,
        detail=detail,
        previous_digest=previous,
        event_digest="",
    )
    event = replace(event, event_digest=_event_digest(event))
    updated = _with_digest(
        replace(
            ledger,
            updated_utc=now,
            audit_events=(*ledger.audit_events, event),
        )
    )
    return updated, event


def record_registry_mutation(
    ledger: GovernanceLedger,
    *,
    subject_id: str,
    actor: str,
    detail: str,
    timestamp: str | None = None,
) -> GovernanceLedger:
    """Record an external evidence-registry mutation without rewriting the
    registry or pretending that it is a review decision."""
    updated, _event = append_audit(
        ledger,
        event_type="registry-mutation",
        subject_id=subject_id,
        actor=actor,
        detail=detail,
        timestamp=timestamp,
    )
    return updated


def _allowed_move(from_stage: EvidenceStage | None, to_stage: EvidenceStage) -> str | None:
    """Return an error message when a move is structurally impossible."""
    if from_stage is None:
        if to_stage is EvidenceStage.OBSERVED:
            return None
        return "first_transition_must_be_observed"
    if from_stage == to_stage:
        return None
    from_index = STAGE_ORDER.index(from_stage)
    to_index = STAGE_ORDER.index(to_stage)
    if to_index == from_index + 1:
        return None
    if to_index < from_index:
        return None
    return "stages_must_advance_one_step"


def apply_transition(
    ledger: GovernanceLedger,
    registry: EvidenceRegistry,
    *,
    subject_id: str,
    to_stage: EvidenceStage,
    actor: str,
    rationale: str,
    evidence_ids: tuple[str, ...] = (),
    reviewer_id: str | None = None,
    timestamp: str | None = None,
) -> TransitionResult:
    """Record one immutable lifecycle transition. Promotions to reviewed,
    candidate, approved and published require a human reviewer; capability
    thresholds from the registry gate correlation and beyond."""
    from_stage = authoritative_stage(ledger, subject_id)
    error = _allowed_move(from_stage, to_stage)
    if error:
        raise GovernanceError(error)
    human_gated = to_stage in HUMAN_GATED_STAGES or (
        from_stage is not None and STAGE_ORDER.index(to_stage) < STAGE_ORDER.index(from_stage)
    )
    if human_gated and (not reviewer_id or reviewer_id in NON_HUMAN_ACTORS):
        raise GovernanceError("human_reviewer_required")
    if not rationale.strip():
        raise GovernanceError("rationale_required")

    thresholds = evaluate_thresholds(registry, ledger.policy)
    capability = stage_capability(to_stage)
    if thresholds[capability] is False:
        raise GovernanceError(f"threshold_not_met:{capability} requires independent radios")

    approval_reviews = [
        item
        for item in ledger.reviews
        if item.subject_id == subject_id and item.decision.value == "approve"
    ]
    if to_stage is EvidenceStage.REVIEWED and not approval_reviews:
        raise GovernanceError("reviewed_stage_requires_approval_review")
    if to_stage is EvidenceStage.CANDIDATE and not approval_reviews:
        raise GovernanceError("candidate_stage_requires_approval_review")
    if to_stage is EvidenceStage.APPROVED:
        proposal = next(
            (
                item
                for item in ledger.proposals
                if item.status.value == "approved"
                and subject_id in item.supporting_device_ids + item.supporting_bundle_ids
            ),
            None,
        )
        if proposal is None:
            raise GovernanceError("approved_stage_requires_approved_proposal")
    if to_stage is EvidenceStage.PUBLISHED:
        publication = next((item for item in ledger.publications if item.publication_id), None)
        if publication is None:
            raise GovernanceError("published_stage_requires_publication")

    now = utc(timestamp)
    transition = LifecycleTransition(
        sequence=len(ledger.transitions) + 1,
        subject_id=subject_id,
        from_stage=from_stage,
        to_stage=to_stage,
        actor=actor,
        reviewer_id=reviewer_id,
        timestamp=now,
        rationale=rationale,
        evidence_ids=tuple(sorted(set(evidence_ids))),
    )
    updated, audit = append_audit(
        ledger,
        event_type="lifecycle-transition",
        subject_id=subject_id,
        actor=actor,
        detail=f"{from_stage.value if from_stage else 'none'}->{to_stage.value}: {rationale}",
        timestamp=now,
    )
    transition = replace(transition, audit_event_id=audit.event_digest)
    updated = _with_digest(
        replace(
            updated,
            updated_utc=now,
            transitions=(*updated.transitions, transition),
        )
    )
    return TransitionResult(updated, transition, audit)


def validate_governance(ledger: GovernanceLedger) -> GovernanceValidation:
    errors: list[str] = []
    warnings: list[str] = []
    if ledger.schema_version != GOVERNANCE_SCHEMA_VERSION:
        errors.append("unsupported_governance_schema")
    expected = _with_digest(replace(ledger, ledger_digest="")).ledger_digest
    if ledger.ledger_digest != expected:
        errors.append("ledger_digest_mismatch")
    sequences = [item.sequence for item in ledger.audit_events]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        errors.append("audit_sequence_not_unique_sorted")
    previous = ""
    for index, event in enumerate(ledger.audit_events):
        if event.previous_digest != previous:
            errors.append(f"audit_chain_break_at:{event.sequence}")
        recomputed = _event_digest(event)
        if event.event_digest != recomputed:
            errors.append(f"audit_event_digest_mismatch:{event.sequence}")
        previous = event.event_digest
        if event.sequence != index + 1:
            errors.append("audit_event_sequence_not_contiguous")
    transition_sequences = [item.sequence for item in ledger.transitions]
    if transition_sequences != sorted(transition_sequences) or len(transition_sequences) != len(
        set(transition_sequences)
    ):
        errors.append("transition_sequence_not_unique_sorted")
    review_ids = [item.review_id for item in ledger.reviews]
    if len(review_ids) != len(set(review_ids)):
        errors.append("review_ids_not_unique")
    proposal_ids = [item.proposal_id for item in ledger.proposals]
    if len(proposal_ids) != len(set(proposal_ids)):
        errors.append("proposal_ids_not_unique")
    if not (ledger.transitions and ledger.transitions[0].from_stage is None):
        if ledger.transitions:
            warnings.append("first_transition_not_observed")
    return GovernanceValidation(
        not errors, tuple(sorted(set(errors))), tuple(sorted(set(warnings)))
    )


def governance_summary(ledger: GovernanceLedger) -> dict[str, Any]:
    return {
        "audit_event_count": len(ledger.audit_events),
        "ledger_digest": ledger.ledger_digest,
        "ledger_id": ledger.ledger_id,
        "proposal_count": len(ledger.proposals),
        "publication_count": len(ledger.publications),
        "review_count": len(ledger.reviews),
        "schema_version": ledger.schema_version,
        "transition_count": len(ledger.transitions),
        "updated_utc": ledger.updated_utc,
    }


__all__ = [
    "GOVERNANCE_SCHEMA_VERSION",
    "GovernanceError",
    "GovernanceSchemaError",
    "GovernanceValidation",
    "TransitionResult",
    "append_audit",
    "apply_transition",
    "create_governance",
    "evaluate_thresholds",
    "governance_from_dict",
    "governance_summary",
    "load_governance",
    "record_registry_mutation",
    "validate_governance",
    "write_governance",
]
