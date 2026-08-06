"""Catalog proposals: immutable from drafting through under-review, approval,
rejection or withdrawal. Production catalogs are never touched here."""

from __future__ import annotations

from dataclasses import replace

from ..evidence_registry import EvidenceRegistry
from .ledger import _with_digest, append_audit, evaluate_thresholds
from .models import (
    CatalogProposal,
    GovernanceError,
    GovernanceLedger,
    ProposalStatus,
    ProposedCatalogEntry,
    sha256_digest,
    utc,
)


def _proposal_identity(
    *,
    created: str,
    reviewer_id: str,
    rationale: str,
    entries: tuple[ProposedCatalogEntry, ...],
) -> str:
    return sha256_digest(
        {
            "created_utc": created,
            "entries": [item.to_dict() for item in entries],
            "rationale": rationale,
            "reviewer_id": reviewer_id,
        }
    )


def _draft_entries_from_registry(registry: EvidenceRegistry) -> tuple[ProposedCatalogEntry, ...]:
    """Deterministically draft one entry per candidate discriminator. Drafting
    is never promotion: entries still require explicit review and approval."""
    entries: list[ProposedCatalogEntry] = []
    for candidate in registry.candidates:
        fields: tuple[tuple[str, str], ...] = (
            ("candidate_id", candidate.candidate_id),
            ("driver_id", candidate.driver_id),
            ("offset", str(candidate.offset)),
            ("length", str(candidate.length)),
            ("probe_definition", candidate.probe_definition),
            ("observed_values", ",".join(candidate.observed_values)),
        )
        entry_id = "entry:sha256:" + sha256_digest(
            {"candidate_id": candidate.candidate_id, "kind": "discriminator"}
        )
        entries.append(
            ProposedCatalogEntry(
                entry_id=entry_id,
                catalog_kind="discriminator",
                fields=fields,
                evidence_ids=tuple(sorted(set(candidate.supporting_bundle_ids))),
            )
        )
    return tuple(sorted(entries, key=lambda item: item.entry_id))


def create_proposal(
    ledger: GovernanceLedger,
    registry: EvidenceRegistry,
    *,
    reviewer_id: str,
    rationale: str,
    entries: tuple[ProposedCatalogEntry, ...] | None = None,
    timestamp: str | None = None,
) -> tuple[GovernanceLedger, CatalogProposal]:
    """Create a catalog proposal. Draft entries are derived from registry
    candidates when none are supplied. The proposal is only a draft: nothing is
    approved yet."""
    if not reviewer_id.strip():
        raise GovernanceError("reviewer_id_required")
    if not rationale.strip():
        raise GovernanceError("rationale_required")
    draft = (
        tuple(sorted(entries, key=lambda item: item.entry_id))
        if entries
        else _draft_entries_from_registry(registry)
    )
    if not draft:
        raise GovernanceError("proposal_requires_supporting_candidates")
    thresholds = evaluate_thresholds(registry, ledger.policy)
    now = utc(timestamp)
    proposal = CatalogProposal(
        proposal_id="proposal:sha256:"
        + _proposal_identity(
            rationale=rationale, reviewer_id=reviewer_id, entries=draft, created=now
        ),
        status=ProposalStatus.DRAFTED,
        rationale=rationale,
        entries=draft,
        supporting_bundle_ids=tuple(sorted({id for item in draft for id in item.evidence_ids})),
        supporting_device_ids=tuple(
            sorted({item.device_id for item in registry.bundles if item.device_id})
        ),
        reviewer_ids=tuple(sorted({reviewer_id})),
        review_ids=(),
        thresholds_satisfied=tuple(
            sorted(key for key, value in thresholds.items() if value is True)
        ),
        created_utc=now,
        updated_utc=now,
    )
    updated, _audit = append_audit(
        ledger,
        event_type="proposal",
        subject_id=proposal.proposal_id,
        actor=reviewer_id,
        detail=f"created ({ProposalStatus.DRAFTED.value}): {rationale}",
        timestamp=now,
    )
    updated = _with_digest(
        replace(
            updated,
            updated_utc=now,
            proposals=tuple(
                sorted((*updated.proposals, proposal), key=lambda item: item.proposal_id)
            ),
        )
    )
    return updated, proposal


def _get_proposal(ledger: GovernanceLedger, proposal_id: str) -> CatalogProposal:
    proposal = next((item for item in ledger.proposals if item.proposal_id == proposal_id), None)
    if proposal is None:
        raise GovernanceError(f"unknown_proposal:{proposal_id}")
    return proposal


def submit_proposal_review(
    ledger: GovernanceLedger,
    proposal_id: str,
    *,
    reviewer_id: str,
    decision: str,
    rationale: str,
    timestamp: str | None = None,
) -> tuple[GovernanceLedger, CatalogProposal]:
    """Transition a draft proposal to under-review and record a reviewer. The
    decision string is descriptive; approval is a separate explicit step."""
    proposal = _get_proposal(ledger, proposal_id)
    now = utc(timestamp)
    reviewer_ids = tuple(sorted(set(proposal.reviewer_ids) | {reviewer_id}))
    status = ProposalStatus.UNDER_REVIEW
    updated = _with_digest(
        replace(
            ledger,
            updated_utc=now,
            proposals=tuple(
                replace(item, status=status, updated_utc=now, reviewer_ids=reviewer_ids)
                if item.proposal_id == proposal_id
                else item
                for item in ledger.proposals
            ),
        )
    )
    updated, _audit = append_audit(
        updated,
        event_type="proposal",
        subject_id=proposal_id,
        actor=reviewer_id,
        detail=f"under-review ({decision}): {rationale}",
        timestamp=now,
    )
    return _with_digest(updated), proposal


def approve_proposal(
    ledger: GovernanceLedger,
    registry: EvidenceRegistry,
    proposal_id: str,
    *,
    reviewer_id: str,
    rationale: str,
    timestamp: str | None = None,
) -> tuple[GovernanceLedger, CatalogProposal]:
    """Approve a catalog proposal. Approval requires: proposal under review, at
    least one approval review on the proposal, the proposal policy threshold met
    by independently verified radios, and no blocking contradictions."""
    proposal = _get_proposal(ledger, proposal_id)
    if not reviewer_id.strip():
        raise GovernanceError("reviewer_id_required")
    if not rationale.strip():
        raise GovernanceError("rationale_required")
    if proposal.status not in {ProposalStatus.DRAFTED, ProposalStatus.UNDER_REVIEW}:
        raise GovernanceError("proposal_not_approvable")
    thresholds = evaluate_thresholds(registry, ledger.policy)
    if not thresholds["proposal_enabled"]:
        raise GovernanceError("proposal_threshold_not_met")
    proposal_reviews = [
        item
        for item in ledger.reviews
        if item.subject_id == proposal_id and item.review_type.value == "proposal"
    ]
    if not any(item.decision.value == "approve" for item in proposal_reviews):
        raise GovernanceError("proposal_requires_approval_review")
    active_devices = {item.device_id for item in registry.bundles if item.device_id}
    missing = set(proposal.supporting_device_ids) - active_devices
    if missing:
        raise GovernanceError("proposal_supporting_evidence_missing")
    now = utc(timestamp)
    updated_proposal = replace(
        proposal,
        status=ProposalStatus.APPROVED,
        updated_utc=now,
        reviewer_ids=tuple(sorted(set(proposal.reviewer_ids) | {reviewer_id})),
        review_ids=tuple(sorted(item.review_id for item in proposal_reviews)),
    )
    updated = _with_digest(
        replace(
            ledger,
            updated_utc=now,
            proposals=tuple(
                replace(item, status=updated_proposal.status, updated_utc=now)
                if item.proposal_id == proposal_id
                else item
                for item in ledger.proposals
            ),
        )
    )
    updated, _audit = append_audit(
        updated,
        event_type="approval",
        subject_id=proposal_id,
        actor=reviewer_id,
        detail=f"approved: {rationale}",
        timestamp=now,
    )
    return _with_digest(updated), updated_proposal


def utc_now(value: str | None) -> str:
    return utc(value)


def _proposal_entry_ids(proposal: CatalogProposal) -> tuple[str, ...]:
    return tuple(item.entry_id for item in proposal.entries)


__all__ = [
    "approve_proposal",
    "create_proposal",
    "submit_proposal_review",
]
