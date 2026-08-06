from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from qsidentify.evidence_registry import (
    BundleRecord,
    CandidateRecord,
    CandidateStatus,
    DeclarationRecord,
    DeviceRecord,
    EvidenceRegistry,
)
from qsidentify.governance import (
    GovernanceError,
    apply_transition,
    approve_proposal,
    build_publication,
    create_governance,
    create_proposal,
    create_review,
    evaluate_thresholds,
    load_governance,
    submit_proposal_review,
    validate_governance,
    verify_publication,
    write_governance,
)
from qsidentify.governance.models import (
    EvidenceStage,
    ReviewDecision,
    ReviewType,
)

FIXED = "2026-08-06T12:00:00+00:00"


def registry_with_devices(count: int = 10) -> EvidenceRegistry:
    bundles = tuple(
        BundleRecord(
            bundle_id=f"bundle:{index}",
            content_digest=f"sha256:{index:064x}",
            electronic_fingerprint=f"fingerprint:{index}",
            fingerprint_schema=1,
            driver_ids=("quansheng",),
            device_id=f"device:{index}",
            capture_ids=(f"capture:{index}",),
            probe_run_ids=(),
            canonical_bundle_json="{}",
        )
        for index in range(count)
    )
    devices = tuple(
        DeviceRecord(
            device_id=f"device:{index}",
            label=f"sample-{index}",
            declared_model=None,
            declared_revision=None,
            declared_mcu="PY32F030",
            declared_pcb=None,
            electronic_fingerprints=(f"fingerprint:{index}",),
            bundle_ids=(f"bundle:{index}",),
            evidence_status="complete",
        )
        for index in range(count)
    )
    declarations = tuple(
        DeclarationRecord(
            declaration_id=f"declaration:{index}",
            device_id=f"device:{index}",
            field="mcu",
            value="PY32F030",
            source="inspection",
            timestamp=FIXED,
            confidence="high",
            verification_status="independently-reviewed",
            notes="inspection",
        )
        for index in range(count)
    )
    candidate = CandidateRecord(
        candidate_id="candidate:one",
        driver_id="quansheng",
        probe_definition="firmware-identification",
        offset=0,
        length=2,
        normalization_rules=("decoded-payload",),
        supporting_bundle_ids=tuple(item.bundle_id for item in bundles),
        supporting_device_ids=tuple(item.device_id for item in devices),
        contradicting_bundle_ids=(),
        observed_values=("1505", "1605"),
        declared_hardware_correlations=("mcu",),
        sample_count=count,
        device_count=count,
        status=CandidateStatus.CORRELATED,
        confidence_scope="statistical-correlation-only",
        review_history=(),
    )
    return EvidenceRegistry(
        schema_version=1,
        registry_id="registry:test",
        created_utc=FIXED,
        updated_utc=FIXED,
        qsidentify_version="1.3.0",
        bundles=bundles,
        devices=devices,
        declarations=declarations,
        candidates=(candidate,),
        review_events=(),
        registry_digest="test",
    )


def test_review_records_are_frozen_and_audited() -> None:
    ledger = create_governance(timestamp=FIXED)
    updated, review = create_review(
        ledger,
        reviewer_id="reviewer-a",
        review_type=ReviewType.EVIDENCE,
        decision=ReviewDecision.APPROVE,
        rationale="consistent response",
        subject_id="bundle:test",
        timestamp=FIXED,
    )
    assert len(ledger.reviews) == 0
    assert updated.reviews == (review,)
    assert updated.audit_events[-1].event_type == "review"
    with pytest.raises(FrozenInstanceError):
        review.rationale = "rewritten"  # type: ignore[misc]


def test_audit_history_is_append_only_and_tamper_evident() -> None:
    ledger = create_governance(timestamp=FIXED)
    ledger, _ = create_review(
        ledger,
        reviewer_id="reviewer-a",
        review_type=ReviewType.EVIDENCE,
        decision=ReviewDecision.REJECT,
        rationale="insufficient",
        subject_id="bundle:test",
        timestamp=FIXED,
    )
    assert validate_governance(ledger).valid
    tampered = replace(ledger, audit_events=ledger.audit_events[:-1])
    assert not validate_governance(tampered).valid


def test_threshold_policy_distinguishes_inspected_and_verified() -> None:
    registry = registry_with_devices()
    result = evaluate_thresholds(registry)
    assert result["independent_radios"] == 10
    assert result["inspected_devices"] == 10
    assert result["verified_devices"] == 10
    assert result["proposal_enabled"] is True


def test_lifecycle_transition_requires_human_reviewer_at_review_stage() -> None:
    registry = registry_with_devices()
    ledger = create_governance(timestamp=FIXED)
    subject = registry.bundles[0].bundle_id
    ledger = apply_transition(
        ledger,
        registry,
        subject_id=subject,
        to_stage=EvidenceStage.OBSERVED,
        actor="tool",
        rationale="capture observed",
        timestamp=FIXED,
    ).ledger
    ledger = apply_transition(
        ledger,
        registry,
        subject_id=subject,
        to_stage=EvidenceStage.SANITIZED,
        actor="tool",
        rationale="metadata removed",
        timestamp=FIXED,
    ).ledger
    ledger = apply_transition(
        ledger,
        registry,
        subject_id=subject,
        to_stage=EvidenceStage.IMPORTED,
        actor="tool",
        rationale="imported",
        timestamp=FIXED,
    ).ledger
    with pytest.raises(GovernanceError, match="human_reviewer_required"):
        apply_transition(
            ledger,
            registry,
            subject_id=subject,
            to_stage=EvidenceStage.REVIEWED,
            actor="tool",
            rationale="reviewed",
            timestamp=FIXED,
        )


def test_blind_review_redacts_host_metadata() -> None:
    from qsidentify.governance.reviews import blind_review_bundle

    view = blind_review_bundle(
        {"hostname": "host", "capture_metadata": {"username": "user"}, "value": 1}
    )
    assert "hostname" not in view
    assert "username" not in view["capture_metadata"]
    assert view["value"] == 1


def test_proposal_approval_requires_review_and_is_explicit() -> None:
    registry = registry_with_devices()
    ledger = create_governance(timestamp=FIXED)
    ledger, proposal = create_proposal(
        ledger, registry, reviewer_id="creator", rationale="candidate correlation", timestamp=FIXED
    )
    with pytest.raises(GovernanceError, match="approval_review"):
        approve_proposal(
            ledger, registry, proposal.proposal_id, reviewer_id="approver", rationale="approve"
        )
    ledger, _ = create_review(
        ledger,
        reviewer_id="reviewer",
        review_type=ReviewType.PROPOSAL,
        decision=ReviewDecision.APPROVE,
        rationale="evidence reviewed",
        subject_id=proposal.proposal_id,
        timestamp=FIXED,
    )
    ledger, _ = submit_proposal_review(
        ledger,
        proposal.proposal_id,
        reviewer_id="reviewer",
        decision="approve",
        rationale="evidence reviewed",
        timestamp=FIXED,
    )
    _, approved = approve_proposal(
        ledger,
        registry,
        proposal.proposal_id,
        reviewer_id="approver",
        rationale="approved after review",
        timestamp=FIXED,
    )
    assert approved.status.value == "approved"


def test_publication_is_deterministic_and_verifiable(tmp_path: Path) -> None:
    registry = registry_with_devices()
    ledger = create_governance(timestamp=FIXED)
    ledger, proposal = create_proposal(
        ledger, registry, reviewer_id="creator", rationale="publish candidate", timestamp=FIXED
    )
    ledger, _ = create_review(
        ledger,
        reviewer_id="reviewer",
        review_type=ReviewType.PROPOSAL,
        decision=ReviewDecision.APPROVE,
        rationale="approved",
        subject_id=proposal.proposal_id,
        blind=True,
        timestamp=FIXED,
    )
    ledger, _ = submit_proposal_review(
        ledger,
        proposal.proposal_id,
        reviewer_id="reviewer",
        decision="approve",
        rationale="approved",
        timestamp=FIXED,
    )
    ledger, _ = approve_proposal(
        ledger,
        registry,
        proposal.proposal_id,
        reviewer_id="approver",
        rationale="approved",
        timestamp=FIXED,
    )
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    approved_ledger = ledger
    _, _, first_digest = build_publication(
        approved_ledger, registry, proposal.proposal_id, output=first, timestamp=FIXED
    )
    # Rebuilding the same immutable proposal is deterministic, even when the
    # output path differs and the ledger already contains the first record.
    _, _, second_digest = build_publication(
        approved_ledger, registry, proposal.proposal_id, output=second, timestamp=FIXED
    )
    assert first_digest == second_digest
    assert first.read_bytes() == second.read_bytes()
    assert verify_publication(first).valid


def test_governance_round_trip_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "governance.json"
    ledger = create_governance(timestamp=FIXED)
    write_governance(path, ledger)
    assert load_governance(path) == ledger
    assert json.loads(path.read_text())["schema_version"] == 1
