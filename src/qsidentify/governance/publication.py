"""Deterministic signed publication packages.

A publication package contains only: an approved catalog, a manifest, member
checksums, review decisions and supporting evidence references. It never
contains firmware binaries, captures or user metadata. Archives are deterministic
ZIPs with fixed timestamps and strict member whitelists.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

from .. import __version__
from ..evidence_registry import EvidenceRegistry
from .ledger import _with_digest, append_audit
from .models import (
    CatalogProposal,
    GovernanceError,
    GovernanceLedger,
    ProposalStatus,
    PublicationRecord,
    sha256_digest,
    utc,
)

PUBLICATION_SCHEMA_VERSION = 1
FIXED_ZIP_DATETIME = (2020, 1, 1, 0, 0, 0)
PUBLICATION_MEMBERS = frozenset(
    {"manifest.json", "catalog.json", "reviews.json", "references.json", "checksums.json"}
)


class PublicationError(GovernanceError):
    """Raised for malformed or unsafe publication packages."""


@dataclass(frozen=True, slots=True)
class PublicationVerification:
    valid: bool
    publication_id: str | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "errors": list(self.errors),
            "publication_id": self.publication_id,
            "valid": self.valid,
            "warnings": list(self.warnings),
        }


def _member(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, FIXED_ZIP_DATETIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info, data


def _canonical(value: object, *, pretty: bool = False) -> bytes:
    if pretty:
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _review_decision_views(
    ledger: GovernanceLedger, proposal: CatalogProposal
) -> list[dict[str, Any]]:
    """Serialize review decisions. Reviewer identity is redacted for blind
    reviews so reviewers stay anonymous unless they opt out."""
    views: list[dict[str, Any]] = []
    subject_ids = {
        proposal.proposal_id,
        *proposal.supporting_bundle_ids,
        *proposal.supporting_device_ids,
    }
    for review in ledger.reviews:
        if review.subject_id not in subject_ids:
            continue
        reviewer = review.reviewer_id if not review.blind else "reviewer:anonymous"
        views.append(
            {
                "blind": review.blind,
                "confidence": review.confidence.value,
                "decision": review.decision.value,
                "rationale": review.rationale,
                "review_id": review.review_id,
                "review_type": review.review_type.value,
                "reviewer_id": reviewer,
                "subject_id": review.subject_id,
                "timestamp": review.timestamp,
            }
        )
    return sorted(views, key=lambda item: (item["review_id"], item["timestamp"]))


def _catalog_entries(proposal: CatalogProposal) -> list[dict[str, Any]]:
    return [entry.to_dict() for entry in proposal.entries]


def build_publication(
    ledger: GovernanceLedger,
    registry: EvidenceRegistry,
    proposal_id: str,
    *,
    output: Path,
    timestamp: str | None = None,
) -> tuple[GovernanceLedger, PublicationRecord, str]:
    """Build a deterministic publication package from an approved proposal.
    Returns (ledger, publication record, sha256 of the package bytes)."""
    proposal = next((item for item in ledger.proposals if item.proposal_id == proposal_id), None)
    if proposal is None:
        raise PublicationError(f"unknown_proposal:{proposal_id}")
    if proposal.status.value != "approved":
        raise PublicationError("publication_requires_approved_proposal")
    approval_reviews = [item for item in ledger.reviews if item.subject_id == proposal_id]
    if not approval_reviews:
        raise PublicationError("publication_requires_review_decisions")
    entry_ids = tuple(item.entry_id for item in proposal.entries)
    review_ids = tuple(
        sorted(
            {
                item.review_id
                for item in ledger.reviews
                if item.subject_id == proposal_id
                or item.subject_id in proposal.supporting_bundle_ids
                or item.subject_id in proposal.supporting_device_ids
            }
        )
    )
    reviewer_ids = tuple(sorted(set(proposal.reviewer_ids)))
    thresholds = tuple(sorted(proposal.thresholds_satisfied))
    device_ids = proposal.supporting_device_ids
    bundle_ids = proposal.supporting_bundle_ids
    now = utc(timestamp)
    identity = sha256_digest(
        {
            "entry_ids": entry_ids,
            "proposal_id": proposal_id,
            "schema_version": PUBLICATION_SCHEMA_VERSION,
        }
    )
    publication_id = "publication:sha256:" + identity

    manifest = {
        "catalog_entries": list(entry_ids),
        "created_by": f"QSIdentify {__version__}",
        "offline": True,
        "proposal_id": proposal_id,
        "publication_id": publication_id,
        "published_utc": now,
        "schema_version": PUBLICATION_SCHEMA_VERSION,
    }
    catalog = {
        "catalog_entries": _catalog_entries(proposal),
        "proposal_id": proposal_id,
        "schema_version": PUBLICATION_SCHEMA_VERSION,
    }
    reviews = {
        "review_decisions": _review_decision_views(ledger, proposal),
        "schema_version": PUBLICATION_SCHEMA_VERSION,
    }
    references = {
        "bundle_ids": list(bundle_ids),
        "device_ids": list(device_ids),
        "review_ids": list(review_ids),
        "reviewer_ids": list(reviewer_ids),
        "schema_version": PUBLICATION_SCHEMA_VERSION,
        "thresholds_satisfied": list(thresholds),
    }
    members: dict[str, bytes] = {
        "manifest.json": _canonical(manifest, pretty=True),
        "catalog.json": _canonical(catalog, pretty=True),
        "reviews.json": _canonical(reviews, pretty=True),
        "references.json": _canonical(references, pretty=True),
    }
    checksums = {
        name: "sha256:" + hashlib.sha256(data).hexdigest() for name, data in members.items()
    }
    members["checksums.json"] = _canonical(
        {
            "checksums": checksums,
            "schema_version": PUBLICATION_SCHEMA_VERSION,
        },
        pretty=True,
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=output.parent, prefix=f".{output.name}.")
    os.close(descriptor)
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for name in sorted(members):
                info, data = _member(name, members[name])
                archive.writestr(info, data, compresslevel=9)
        os.replace(temporary, output)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    package_sha256 = "sha256:" + hashlib.sha256(output.read_bytes()).hexdigest()
    publication = PublicationRecord(
        publication_id=publication_id,
        proposal_id=proposal_id,
        schema_version=PUBLICATION_SCHEMA_VERSION,
        catalog_entry_ids=entry_ids,
        review_ids=review_ids,
        bundle_ids=bundle_ids,
        device_ids=device_ids,
        reviewer_ids=reviewer_ids,
        thresholds_satisfied=thresholds,
        built_utc=now,
        sha256=package_sha256,
    )
    updated, _audit = append_audit(
        ledger,
        event_type="publication",
        subject_id=publication_id,
        actor="publication-builder",
        detail=f"built from {proposal_id}",
        timestamp=now,
    )
    updated = _with_digest(
        replace(
            updated,
            updated_utc=now,
            publications=tuple(
                sorted(
                    (*updated.publications, publication),
                    key=lambda item: item.publication_id,
                )
            ),
            proposals=tuple(
                replace(item, status=ProposalStatus.PUBLISHED, publication_id=publication_id)
                if item.proposal_id == proposal_id
                else item
                for item in updated.proposals
            ),
        )
    )
    return updated, publication, package_sha256


def _safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def _contains_network(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            _contains_network(key) or _contains_network(child) for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_network(item) for item in value)
    return isinstance(value, str) and value.lower().startswith(("http://", "https://"))


def verify_publication(path: Path) -> PublicationVerification:
    """Strictly verify a publication package without extracting it. Checks
    member whitelist, traversal safety, executables, manifest schema, and every
    member against the declared SHA-256 manifest."""
    errors: list[str] = []
    warnings: list[str] = []
    publication_id: str | None = None
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = tuple(info.filename for info in infos)
            if len(names) != len(set(names)):
                errors.append("duplicate_archive_member")
            if names != tuple(sorted(names)):
                errors.append("archive_members_not_sorted")
            for info in infos:
                name = info.filename
                if not _safe_name(name):
                    errors.append(f"unsafe_archive_path:{name}")
                if name not in PUBLICATION_MEMBERS:
                    errors.append(f"unexpected_archive_member:{name}")
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    errors.append(f"symlink_archive_member:{name}")
                if mode & 0o111:
                    errors.append(f"executable_archive_member:{name}")
            if "manifest.json" not in names:
                errors.append("missing_manifest")
                manifest: dict[str, Any] = {}
            else:
                try:
                    value = json.loads(archive.read("manifest.json"))
                    manifest = value if isinstance(value, dict) else {}
                except (json.JSONDecodeError, UnicodeError):
                    manifest = {}
                    errors.append("invalid_manifest")
            if manifest.get("schema_version") != PUBLICATION_SCHEMA_VERSION:
                errors.append("unsupported_publication_schema")
            publication_id = manifest.get("publication_id")
            if not isinstance(publication_id, str):
                errors.append("missing_publication_id")
            if manifest.get("offline") is not True:
                errors.append("publication_not_marked_offline")
            if _contains_network(manifest):
                errors.append("network_url_in_manifest")
            for name in ("catalog.json", "reviews.json", "references.json"):
                if name not in names:
                    errors.append(f"missing_member:{name}")
            if "checksums.json" not in names:
                errors.append("missing_checksums")
            else:
                try:
                    checksum_value = json.loads(archive.read("checksums.json"))
                    checksums = (
                        checksum_value.get("checksums") if isinstance(checksum_value, dict) else {}
                    )
                except (json.JSONDecodeError, UnicodeError):
                    checksums = {}
                    errors.append("invalid_checksums")
                if not isinstance(checksums, dict):
                    checksums = {}
                    errors.append("invalid_checksums")
                for info in infos:
                    name = info.filename
                    if name == "checksums.json":
                        continue
                    declared = checksums.get(name)
                    actual = "sha256:" + hashlib.sha256(archive.read(name)).hexdigest()
                    if declared != actual:
                        errors.append(f"checksum_mismatch:{name}")
            for name in ("catalog.json", "reviews.json", "references.json"):
                try:
                    member_value = json.loads(archive.read(name))
                except (json.JSONDecodeError, UnicodeError):
                    errors.append(f"invalid_json:{name}")
                    continue
                if _contains_network(member_value):
                    errors.append(f"network_url_in_member:{name}")
            try:
                catalog_value = json.loads(archive.read("catalog.json"))
            except (json.JSONDecodeError, UnicodeError):
                catalog_value = {}
            catalog_entries = (
                catalog_value.get("catalog_entries") if isinstance(catalog_value, dict) else []
            )
            if not isinstance(catalog_entries, list) or not catalog_entries:
                errors.append("catalog_has_no_entries")
            serialized = json.dumps(catalog_value).lower()
            if any(token in serialized for token in (".bin", ".hex", ".img", ".uf2", ".fw")):
                errors.append("forbidden_binary_reference_in_catalog")
    except (OSError, zipfile.BadZipFile) as exc:
        return PublicationVerification(False, None, (f"invalid_archive:{exc}",), ())
    return PublicationVerification(
        not errors,
        publication_id,
        tuple(sorted(set(errors))),
        tuple(sorted(set(warnings))),
    )


def inspect_publication(path: Path) -> dict[str, Any]:
    verification = verify_publication(path)
    return {
        "member_count": _zip_member_count(path),
        "publication_id": verification.publication_id,
        "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        "valid": verification.valid,
    }


def _zip_member_count(path: Path) -> int:
    try:
        with zipfile.ZipFile(path) as archive:
            return len(archive.namelist())
    except (OSError, zipfile.BadZipFile):
        return 0


__all__ = [
    "FIXED_ZIP_DATETIME",
    "PUBLICATION_MEMBERS",
    "PUBLICATION_SCHEMA_VERSION",
    "PublicationError",
    "PublicationVerification",
    "build_publication",
    "inspect_publication",
    "verify_publication",
]
