"""M2.0 trusted evidence governance: immutable lifecycle, reviews, proposals,
publication packages and append-only audit events.

Everything in this package is offline, deterministic and side-effect free.
It never performs serial I/O and never mutates production catalogs directly.
Production catalogs may only change through explicitly approved publication
packages built by ``build_publication``.
"""

from .ledger import (
    GOVERNANCE_SCHEMA_VERSION,
    GovernanceError,
    GovernanceSchemaError,
    GovernanceValidation,
    apply_transition,
    create_governance,
    evaluate_thresholds,
    governance_summary,
    load_governance,
    record_registry_mutation,
    validate_governance,
    write_governance,
)
from .models import (
    AuditEvent,
    CatalogProposal,
    ConfidenceLevel,
    ConfidenceProfile,
    EvidencePolicy,
    EvidenceStage,
    GovernanceLedger,
    LifecycleTransition,
    ProposalStatus,
    ProposedCatalogEntry,
    PublicationRecord,
    ReviewDecision,
    ReviewRecord,
    ReviewType,
)
from .policy import confidence_profile
from .proposals import approve_proposal, create_proposal, submit_proposal_review
from .publication import (
    PublicationError,
    PublicationVerification,
    build_publication,
    inspect_publication,
    verify_publication,
)
from .reviews import create_review

__all__ = [
    "AuditEvent",
    "CatalogProposal",
    "ConfidenceLevel",
    "ConfidenceProfile",
    "EvidencePolicy",
    "EvidenceStage",
    "GOVERNANCE_SCHEMA_VERSION",
    "GovernanceError",
    "GovernanceLedger",
    "GovernanceSchemaError",
    "GovernanceValidation",
    "LifecycleTransition",
    "ProposedCatalogEntry",
    "ProposalStatus",
    "PublicationError",
    "PublicationRecord",
    "PublicationVerification",
    "ReviewDecision",
    "ReviewRecord",
    "ReviewType",
    "approve_proposal",
    "apply_transition",
    "build_publication",
    "confidence_profile",
    "create_governance",
    "create_proposal",
    "create_review",
    "evaluate_thresholds",
    "inspect_publication",
    "governance_summary",
    "load_governance",
    "record_registry_mutation",
    "submit_proposal_review",
    "validate_governance",
    "verify_publication",
    "write_governance",
]
