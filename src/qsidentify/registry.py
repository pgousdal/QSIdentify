"""Stable, synchronous, offline evidence-registry API."""

from .evidence_registry import (
    DuplicateEvidenceError,
    EvidenceRegistry,
    RegistryError,
    RegistryMutation,
    RegistrySchemaError,
    RegistryValidation,
    add_evidence_bundle,
    analyze_registry,
    create_registry,
    load_registry,
    validate_registry,
)

__all__ = [
    "DuplicateEvidenceError",
    "EvidenceRegistry",
    "RegistryError",
    "RegistryMutation",
    "RegistrySchemaError",
    "RegistryValidation",
    "add_evidence_bundle",
    "analyze_registry",
    "create_registry",
    "load_registry",
    "validate_registry",
]
