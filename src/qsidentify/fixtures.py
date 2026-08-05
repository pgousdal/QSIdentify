from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capture import read_capture


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
    return FixtureValidation(not errors, len(entries), tuple(errors))


__all__ = ["FixtureValidation", "validate_fixture_manifest"]
