"""M2.0 evidence thresholds and structured scientific confidence.

Thresholds are project policy, never scientific proof. They gate which evidence
stages a project may reach. Confidence is always reported as independent,
never automatically combined.
"""

from __future__ import annotations

from typing import Any

from ..evidence_registry import EvidenceRegistry
from .models import (
    ConfidenceLevel,
    ConfidenceProfile,
    EvidencePolicy,
    EvidenceStage,
    GovernanceLedger,
)


def _device_counts(registry: EvidenceRegistry) -> dict[str, int]:
    """Count devices by inspection status using registry declarations.

    Independent radios are devices with at least one registered bundle.
    Inspected radios additionally carry a self-inspected or independently
    reviewed declaration. Verified radios carry an independently reviewed
    declaration on an evidence-bearing device.
    """
    active = [item for item in registry.declarations if item.verification_status != "withdrawn"]
    inspected = {
        item.device_id
        for item in active
        if item.verification_status in {"self-inspected", "independently-reviewed"}
        and item.field in {"mcu", "pcb_revision", "hardware_revision"}
    }
    verified = {
        item.device_id
        for item in active
        if item.verification_status == "independently-reviewed"
        and item.field in {"mcu", "pcb_revision", "hardware_revision"}
    }
    device_ids = {item.device_id for item in registry.devices if item.device_id}
    bundle_devices = {item.device_id for item in registry.bundles if item.device_id is not None}
    return {
        "independent_radios": len(bundle_devices),
        "declared_devices": len(device_ids),
        "inspected_devices": len(inspected),
        "verified_devices": len(verified),
    }


def evaluate_thresholds(
    registry: EvidenceRegistry, policy: EvidencePolicy | None = None
) -> dict[str, Any]:
    """Evaluate which lifecycle capabilities are enabled by the evidence in a
    registry. Returns project policy, not scientific proof."""
    if policy is None:
        policy = EvidencePolicy()
    counts = _device_counts(registry)
    independent = counts["independent_radios"]
    inspected = counts["inspected_devices"]
    verified = counts["verified_devices"]
    return {
        **counts,
        "comparison_enabled": independent >= policy.comparison_device_count,
        "correlation_enabled": independent >= policy.correlation_device_count,
        "proposal_enabled": verified >= policy.proposal_device_count,
        "review_enabled": inspected >= policy.review_device_count,
        "stability_enabled": independent >= policy.stability_device_count,
    }


def _level(value: bool) -> ConfidenceLevel:
    return ConfidenceLevel.HIGH if value else ConfidenceLevel.NONE


def confidence_profile(registry: EvidenceRegistry, ledger: GovernanceLedger) -> ConfidenceProfile:
    """Derive a structured confidence profile from observed evidence and review
    history. Fields are independent and intentionally never aggregated."""
    candidates = registry.candidates
    correlated = [item for item in candidates if item.status.value in {"correlated", "candidate"}]
    approved_reviews = [item for item in ledger.reviews if item.decision.value == "approve"]
    published = [item for item in ledger.publications if item.publication_id]
    return ConfidenceProfile(
        transport=ConfidenceLevel.HIGH if registry.bundles else ConfidenceLevel.NONE,
        protocol=ConfidenceLevel.HIGH if registry.bundles else ConfidenceLevel.NONE,
        firmware=ConfidenceLevel.HIGH if registry.bundles else ConfidenceLevel.NONE,
        fingerprint=ConfidenceLevel.HIGH if registry.bundles else ConfidenceLevel.NONE,
        statistical=_level(bool(correlated)),
        review=_level(bool(approved_reviews)),
        catalog=_level(bool(published)),
    )


def stage_capability(stage: EvidenceStage) -> str:
    """Name the project capability a stage depends on. Used for gating."""
    capabilities = {
        EvidenceStage.OBSERVED: "stability_enabled",
        EvidenceStage.SANITIZED: "stability_enabled",
        EvidenceStage.IMPORTED: "stability_enabled",
        EvidenceStage.REVIEWED: "stability_enabled",
        EvidenceStage.CORRELATED: "correlation_enabled",
        EvidenceStage.CANDIDATE: "review_enabled",
        EvidenceStage.APPROVED: "proposal_enabled",
        EvidenceStage.PUBLISHED: "proposal_enabled",
    }
    return capabilities.get(stage, "stability_enabled")


__all__ = [
    "confidence_profile",
    "evaluate_thresholds",
    "stage_capability",
]
