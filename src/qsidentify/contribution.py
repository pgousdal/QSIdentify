from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__
from .evidence import validate_bundle
from .evidence_registry import (
    Conflict,
    EvidenceRegistry,
    RegistryMutation,
    add_evidence_bundle,
)

CONTRIBUTION_SCHEMA_VERSION = 1
FIXED_ZIP_DATETIME = (2020, 1, 1, 0, 0, 0)
FORBIDDEN_SUFFIXES = {
    ".bin",
    ".exe",
    ".hex",
    ".img",
    ".msi",
    ".sh",
    ".bat",
    ".cmd",
    ".ps1",
    ".so",
    ".dll",
    ".elf",
    ".uf2",
}


class ContributionError(ValueError):
    """Raised for malformed or unsafe contribution archives."""


@dataclass(frozen=True, slots=True)
class ContributionReview:
    classification: str
    contribution_id: str | None
    bundle_count: int
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    member_names: tuple[str, ...]

    @property
    def safe(self) -> bool:
        return self.classification in {
            "safe-to-import",
            "safe-with-warnings",
            "requires-manual-review",
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ContributionImportPlan:
    contribution_id: str
    bundle_ids: tuple[str, ...]
    classifications: tuple[str, ...]
    blocking_conflicts: tuple[dict[str, Any], ...]
    mutation: RegistryMutation

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocking_conflicts": list(self.blocking_conflicts),
            "bundle_ids": list(self.bundle_ids),
            "classifications": list(self.classifications),
            "contribution_id": self.contribution_id,
            "imported_bundle_ids": list(self.mutation.imported_bundle_ids),
            "skipped_bundle_ids": list(self.mutation.skipped_bundle_ids),
        }


def _canonical(value: object, *, pretty: bool = False) -> bytes:
    if pretty:
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _member(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, FIXED_ZIP_DATETIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info, data


def create_contribution(
    bundle_paths: tuple[Path, ...],
    output: Path,
    *,
    declarations: tuple[dict[str, Any], ...] = (),
    notes: str = "",
) -> str:
    if not bundle_paths:
        raise ContributionError("At least one evidence bundle is required.")
    members: list[tuple[str, bytes]] = []
    manifest_bundles: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in bundle_paths:
        ok, errors = validate_bundle(path)
        if not ok:
            raise ContributionError(f"Invalid evidence bundle {path.name}: {'; '.join(errors)}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        data = _canonical(raw, pretty=True)
        digest = _digest(data)
        name = f"bundles/{digest}.json"
        if digest in seen:
            continue
        seen.add(digest)
        members.append((name, data))
        manifest_bundles.append({"path": name, "sha256": digest})
    declaration_data = _canonical(list(declarations), pretty=True)
    if declarations:
        members.append(("declarations.json", declaration_data))
    identity_projection = {
        "bundles": manifest_bundles,
        "declarations_sha256": _digest(declaration_data) if declarations else None,
        "notes": notes,
        "schema_version": CONTRIBUTION_SCHEMA_VERSION,
    }
    contribution_id = "contribution:sha256:" + _digest(_canonical(identity_projection))
    manifest = {
        **identity_projection,
        "contribution_id": contribution_id,
        "created_by": f"QSIdentify {__version__}",
        "offline": True,
    }
    members.append(("manifest.json", _canonical(manifest, pretty=True)))
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
            for name, data in sorted(members):
                info, content = _member(name, data)
                archive.writestr(info, content, compresslevel=9)
        os.replace(temporary, output)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return contribution_id


def _safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def _contains_url(value: object) -> bool:
    if isinstance(value, dict):
        return any(_contains_url(key) or _contains_url(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_url(item) for item in value)
    return isinstance(value, str) and value.lower().startswith(("http://", "https://"))


def review_contribution(path: Path) -> ContributionReview:
    errors: list[str] = []
    warnings: list[str] = []
    contribution_id: str | None = None
    bundle_count = 0
    names: tuple[str, ...] = ()
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
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    errors.append(f"symlink_archive_member:{name}")
                if mode & 0o111:
                    errors.append(f"executable_archive_member:{name}")
                if PurePosixPath(name).suffix.lower() in FORBIDDEN_SUFFIXES:
                    errors.append(f"forbidden_file_type:{name}")
            if "manifest.json" not in names:
                errors.append("missing_manifest")
                manifest: dict[str, Any] = {}
            else:
                try:
                    manifest_value = json.loads(archive.read("manifest.json"))
                    manifest = manifest_value if isinstance(manifest_value, dict) else {}
                except (KeyError, json.JSONDecodeError, UnicodeError):
                    manifest = {}
                    errors.append("invalid_manifest")
            if manifest.get("schema_version") != CONTRIBUTION_SCHEMA_VERSION:
                errors.append("unsupported_contribution_schema")
            contribution_id = manifest.get("contribution_id")
            if not isinstance(contribution_id, str):
                errors.append("missing_contribution_id")
            if _contains_url(manifest):
                errors.append("network_url_in_manifest")
            if "declarations.json" in names:
                warnings.append("physical_declarations_require_manual_review")
                declaration_data = archive.read("declarations.json")
                if _digest(declaration_data) != manifest.get("declarations_sha256"):
                    errors.append("declaration_digest_mismatch")
            bundles = manifest.get("bundles", [])
            if not isinstance(bundles, list):
                errors.append("invalid_bundle_manifest")
                bundles = []
            bundle_count = len(bundles)
            digests: set[str] = set()
            with tempfile.TemporaryDirectory(prefix="qsidentify-contribution-") as temporary:
                root = Path(temporary)
                for entry in bundles:
                    if not isinstance(entry, dict):
                        errors.append("invalid_bundle_manifest_entry")
                        continue
                    entry_name = entry.get("path")
                    expected = entry.get("sha256")
                    if (
                        not isinstance(entry_name, str)
                        or entry_name not in names
                        or not _safe_name(entry_name)
                    ):
                        errors.append(f"missing_bundle_member:{entry_name}")
                        continue
                    data = archive.read(entry_name)
                    actual = _digest(data)
                    if actual != expected:
                        errors.append(f"bundle_digest_mismatch:{entry_name}")
                    if actual in digests:
                        warnings.append("duplicate_bundle_content")
                    digests.add(actual)
                    target = root / f"{actual}.json"
                    target.write_bytes(data)
                    ok, bundle_errors = validate_bundle(target)
                    if not ok:
                        errors.extend(f"invalid_bundle:{error}" for error in bundle_errors)
                    try:
                        raw = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    captures = raw.get("captures", []) if isinstance(raw, dict) else []
                    if any(
                        not isinstance(item.get("capture_metadata"), dict)
                        or item["capture_metadata"].get("sanitized") is not True
                        for item in captures
                    ):
                        errors.append(f"unsanitized_bundle:{entry_name}")
    except (OSError, zipfile.BadZipFile) as exc:
        return ContributionReview("rejected", None, 0, (f"invalid_archive:{exc}",), (), ())
    errors = sorted(set(errors))
    warnings = sorted(set(warnings))
    if errors:
        classification = "rejected"
    elif "physical_declarations_require_manual_review" in warnings:
        classification = "requires-manual-review"
    elif warnings:
        classification = "safe-with-warnings"
    else:
        classification = "safe-to-import"
    return ContributionReview(
        classification,
        contribution_id,
        bundle_count,
        tuple(errors),
        tuple(warnings),
        names,
    )


def inspect_contribution(path: Path) -> dict[str, Any]:
    review = review_contribution(path)
    return {
        "bundle_count": review.bundle_count,
        "classification": review.classification,
        "contribution_id": review.contribution_id,
        "member_names": list(review.member_names),
        "sha256": _digest(path.read_bytes()),
    }


def validate_contribution(path: Path) -> ContributionReview:
    return review_contribution(path)


def plan_contribution_import(
    registry: EvidenceRegistry,
    contribution_path: Path,
    *,
    timestamp: str | None = None,
) -> ContributionImportPlan:
    review = review_contribution(contribution_path)
    if not review.safe or review.contribution_id is None:
        raise ContributionError("Contribution is not safe to import: " + "; ".join(review.errors))
    current = registry
    imported: list[str] = []
    skipped: list[str] = []
    relationships: list[str] = []
    conflicts: list[Conflict] = []
    with zipfile.ZipFile(contribution_path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        declarations = (
            json.loads(archive.read("declarations.json"))
            if "declarations.json" in archive.namelist()
            else []
        )
        with tempfile.TemporaryDirectory(prefix="qsidentify-import-") as temporary:
            root = Path(temporary)
            for index, entry in enumerate(manifest["bundles"], start=1):
                target = root / f"bundle-{index}.json"
                bundle = json.loads(archive.read(entry["path"]))
                device_label = None
                if index == 1 and declarations:
                    bundle["declarations"] = declarations
                    declared_label = declarations[0].get("device_label")
                    device_label = str(declared_label) if declared_label else None
                target.write_bytes(_canonical(bundle, pretty=True))
                mutation = add_evidence_bundle(
                    current,
                    target,
                    device_label=device_label,
                    contribution_id=review.contribution_id,
                    timestamp=timestamp,
                    reject_duplicates=False,
                )
                current = mutation.registry
                imported.extend(mutation.imported_bundle_ids)
                skipped.extend(mutation.skipped_bundle_ids)
                relationships.extend(mutation.relationships)
                conflicts.extend(mutation.conflicts)
    aggregate = RegistryMutation(
        current,
        tuple(sorted(imported)),
        tuple(sorted(skipped)),
        tuple(sorted(set(relationships))),
        tuple(sorted(set(conflicts), key=lambda item: (item.code, item.subject_id))),
    )
    return ContributionImportPlan(
        review.contribution_id,
        tuple(sorted(imported + skipped)),
        aggregate.relationships,
        tuple(item.to_dict() for item in aggregate.conflicts if item.severity == "blocking"),
        aggregate,
    )


__all__ = [
    "CONTRIBUTION_SCHEMA_VERSION",
    "ContributionError",
    "ContributionImportPlan",
    "ContributionReview",
    "create_contribution",
    "inspect_contribution",
    "plan_contribution_import",
    "review_contribution",
    "validate_contribution",
]
