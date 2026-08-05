from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capture import read_capture
from .evidence_registry import load_registry


@dataclass(frozen=True, slots=True)
class FixtureValidation:
    ok: bool
    checked: int
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"checked": self.checked, "errors": list(self.errors), "ok": self.ok}


def validate_fixture_manifest(root: Path) -> FixtureValidation:
    errors: list[str] = []
    try:
        manifest = json.loads((root / "manifest.json").read_text())
        entries = manifest["entries"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return FixtureValidation(False, 0, (f"Invalid fixture manifest: {exc}",))
    paths = [entry.get("path") for entry in entries]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        errors.append("Manifest paths must be unique and sorted.")
    actual = sorted(
        path.relative_to(root).as_posix() for path in (root / "captures").glob("*.json")
    )
    if paths != actual:
        errors.append("Manifest capture list does not match committed captures.")
    for entry in entries:
        path = root / entry["path"]
        if not path.is_file():
            errors.append(f"Missing fixture: {entry['path']}")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            errors.append(f"Digest mismatch: {entry['path']}")
            continue
        try:
            capture = read_capture(path)
        except ValueError as exc:
            errors.append(f"Invalid capture {entry['path']}: {exc}")
            continue
        expected = (
            capture.schema_version,
            capture.driver_id,
            capture.stream_classification.value,
            capture.report.message_type.value,
            capture.report.reported_version,
        )
        stored = (
            entry["schema_version"],
            entry["driver_id"],
            entry["classification"],
            entry["message_type"],
            entry["reported_version"],
        )
        if expected != stored:
            errors.append(f"Decoded metadata mismatch: {entry['path']}")
    checked = len(entries)
    registry_manifest = root / "registry-manifest.json"
    if registry_manifest.is_file():
        try:
            registry_entries = json.loads(registry_manifest.read_text())["entries"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"Invalid registry fixture manifest: {exc}")
            registry_entries = []
        registry_paths = [entry.get("path") for entry in registry_entries]
        if registry_paths != sorted(registry_paths) or len(registry_paths) != len(
            set(registry_paths)
        ):
            errors.append("Registry fixture paths must be unique and sorted.")
        for entry in registry_entries:
            path = root / entry["path"]
            checked += 1
            if not path.is_file():
                errors.append(f"Missing registry fixture: {entry['path']}")
                continue
            if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
                errors.append(f"Registry fixture digest mismatch: {entry['path']}")
                continue
            try:
                if entry["kind"] == "empty-registry":
                    load_registry(path)
                else:
                    parsed = json.loads(path.read_text())
                    if parsed.get("schema_version") != entry["schema_version"]:
                        errors.append(f"Registry fixture schema mismatch: {entry['path']}")
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                errors.append(f"Invalid registry fixture {entry['path']}: {exc}")
    return FixtureValidation(not errors, checked, tuple(errors))


__all__ = ["FixtureValidation", "validate_fixture_manifest"]
