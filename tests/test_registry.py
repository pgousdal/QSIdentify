from __future__ import annotations

import json
import stat
import zipfile
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qsidentify.cli import app
from qsidentify.contribution import (
    create_contribution,
    plan_contribution_import,
    review_contribution,
)
from qsidentify.evidence import export_bundle
from qsidentify.evidence_registry import (
    CandidateStatus,
    DuplicateEvidenceError,
    RegistrySchemaError,
    add_evidence_bundle,
    analyze_registry,
    catalog_proposal,
    create_registry,
    detect_conflicts,
    load_registry,
    propose_discriminator,
    registry_from_dict,
    remove_evidence_bundle,
    validate_registry,
    write_registry,
)
from qsidentify.hardening import APPROVED_COMMAND_INVENTORY_SHA256

PHYSICAL = Path("tests/fixtures/captures/uv-k5-8-2.01.36.json")
FIXED = "2026-08-05T12:00:00+00:00"


def _bundle(tmp_path: Path, name: str = "bundle.json", *, device: str | None = None) -> Path:
    path = tmp_path / name
    export_bundle((PHYSICAL,), path, "registry test")
    if device is not None:
        raw = json.loads(path.read_text())
        raw["captures"][0]["capture_metadata"]["physical_device_group"] = device
        path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    return path


def _declared_bundle(
    tmp_path: Path,
    name: str,
    device: str,
    declarations: list[dict[str, str]],
) -> Path:
    path = _bundle(tmp_path, name, device=device)
    raw = json.loads(path.read_text())
    raw["declarations"] = [
        {
            "confidence": "user-supplied",
            "notes": "physical inspection",
            "source": "user-input",
            "timestamp": FIXED,
            "verification_status": "self-inspected",
            **item,
        }
        for item in declarations
    ]
    path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    return path


def _candidate_bundle(tmp_path: Path, name: str, device: str, value: str, mcu: str) -> Path:
    path = _declared_bundle(
        tmp_path,
        name,
        device,
        [{"field": "mcu", "value": mcu}],
    )
    raw = json.loads(path.read_text())
    stable = raw["fingerprint"]["stable_payload_values_hex"]
    raw["fingerprint"]["stable_payload_values_hex"] = value + stable[4:]
    raw["fingerprint"]["fingerprint_id"] = f"qsfingerprint:v1:sha256:{value:0<64}"
    path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    return path


def test_registry_creation_round_trip_and_immutability(tmp_path: Path) -> None:
    first = create_registry(timestamp=FIXED, registry_label="fixture")
    second = create_registry(timestamp=FIXED, registry_label="fixture")
    assert first == second
    path = tmp_path / "registry.json"
    write_registry(path, first)
    assert load_registry(path) == first
    assert path.read_text().endswith("\n")
    with pytest.raises(FrozenInstanceError):
        first.registry_id = "changed"  # type: ignore[misc]


def test_committed_registry_fixture_and_manifest() -> None:
    root = Path("tests/fixtures")
    manifest = json.loads((root / "registry-manifest.json").read_text())
    assert [item["path"] for item in manifest["entries"]] == sorted(
        item["path"] for item in manifest["entries"]
    )
    import hashlib

    for entry in manifest["entries"]:
        path = root / entry["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
        if entry["kind"] == "empty-registry":
            assert load_registry(path).schema_version == entry["schema_version"]
        else:
            assert json.loads(path.read_text())["schema_version"] == entry["schema_version"]


def test_registry_schema_and_digest_validation() -> None:
    registry = create_registry(timestamp=FIXED)
    raw = registry.to_dict()
    raw["schema_version"] = 99
    with pytest.raises(RegistrySchemaError, match="Unsupported"):
        registry_from_dict(raw)
    assert validate_registry(replace(registry, registry_digest="bad")).valid is False


def test_registry_rejects_forbidden_host_metadata() -> None:
    registry = create_registry(timestamp=FIXED)
    unsafe = replace(registry, registry_id="/home/person/registry")
    errors = validate_registry(unsafe).errors
    assert any("forbidden_metadata:absolute-home-path" in item for item in errors)


def test_add_duplicate_content_and_removal_audit(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    registry = create_registry(timestamp=FIXED)
    first = add_evidence_bundle(registry, bundle, timestamp=FIXED)
    with pytest.raises(DuplicateEvidenceError):
        add_evidence_bundle(first.registry, bundle, timestamp=FIXED)
    removed = remove_evidence_bundle(first.registry, first.imported_bundle_ids[0], timestamp=FIXED)
    assert removed.bundles == ()
    assert removed.review_events[-1].action == "bundle-removed"


def test_distinct_bundle_ids_can_have_duplicate_content(tmp_path: Path) -> None:
    first_path = _bundle(tmp_path, "first.json")
    raw = json.loads(first_path.read_text())
    raw["bundle_id"] = "bundle:local:first"
    first_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    second_path = tmp_path / "second.json"
    raw["bundle_id"] = "bundle:local:second"
    second_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    registry = create_registry(timestamp=FIXED)
    registry = add_evidence_bundle(registry, first_path, timestamp=FIXED).registry
    mutation = add_evidence_bundle(registry, second_path, timestamp=FIXED)
    assert "content duplicate" in mutation.relationships
    assert "same fingerprint" in mutation.relationships
    assert "probable same evidence set" in mutation.relationships


def test_repeated_runs_from_one_device_do_not_inflate_device_count(tmp_path: Path) -> None:
    first = _bundle(tmp_path, "one.json", device="sample-a")
    second = _bundle(tmp_path, "two.json", device="sample-a")
    raw = json.loads(second.read_text())
    raw["bundle_id"] = "bundle:local:second-run"
    second.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    registry = create_registry(timestamp=FIXED)
    registry = add_evidence_bundle(registry, first, timestamp=FIXED).registry
    registry = add_evidence_bundle(registry, second, timestamp=FIXED).registry
    analysis = analyze_registry(registry)
    assert analysis["bundle_count"] == 2
    assert analysis["capture_count"] == 2
    assert analysis["device_count"] == 1
    assert analysis["common_prefix_length"] == 20
    assert analysis["common_suffix_length"] == 20
    assert analysis["device_stability"]
    assert analysis["declared_mcu_groups"] == {"unknown": 1}


def test_same_fingerprint_does_not_merge_different_devices(tmp_path: Path) -> None:
    registry = create_registry(timestamp=FIXED)
    registry = add_evidence_bundle(
        registry, _bundle(tmp_path, "a.json", device="sample-a"), timestamp=FIXED
    ).registry
    second = _bundle(tmp_path, "b.json", device="sample-b")
    raw = json.loads(second.read_text())
    raw["bundle_id"] = "bundle:local:b"
    second.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    mutation = add_evidence_bundle(registry, second, timestamp=FIXED)
    assert len(mutation.registry.devices) == 2
    assert "same fingerprint" in mutation.relationships


def test_conflicting_mcu_and_pcb_declarations_are_blocking(tmp_path: Path) -> None:
    bundle = _declared_bundle(
        tmp_path,
        "conflict.json",
        "sample-a",
        [
            {"field": "mcu", "value": "DP32G030"},
            {"field": "mcu", "value": "PY32F030"},
            {"field": "pcb_revision", "value": "V1"},
            {"field": "pcb_revision", "value": "V2"},
        ],
    )
    registry = add_evidence_bundle(
        create_registry(timestamp=FIXED), bundle, timestamp=FIXED
    ).registry
    codes = {item.code for item in detect_conflicts(registry)}
    assert {"device_mcu_conflict", "device_pcb_conflict"} <= codes
    proposal = catalog_proposal(registry)
    assert proposal["blocking_conflicts"]
    assert proposal["candidate_hardware_mappings"] == []


def test_one_device_cannot_satisfy_discriminator_threshold(tmp_path: Path) -> None:
    registry = add_evidence_bundle(
        create_registry(timestamp=FIXED),
        _bundle(tmp_path, device="sample-a"),
        timestamp=FIXED,
    ).registry
    proposed = propose_discriminator(
        registry,
        offset=0,
        length=2,
        driver_id="quansheng",
        timestamp=FIXED,
    )
    candidate = proposed.candidates[0]
    assert candidate.device_count == 1
    assert candidate.status is CandidateStatus.INSUFFICIENT
    assert candidate.status is not CandidateStatus.VERIFIED


def test_driver_mismatch_produces_no_candidate_support(tmp_path: Path) -> None:
    registry = add_evidence_bundle(
        create_registry(timestamp=FIXED), _bundle(tmp_path), timestamp=FIXED
    ).registry
    candidate = propose_discriminator(
        registry, offset=0, length=1, driver_id="other", timestamp=FIXED
    ).candidates[0]
    assert candidate.sample_count == 0
    assert candidate.status is CandidateStatus.INSUFFICIENT


def test_three_devices_may_produce_correlation_but_never_verification(tmp_path: Path) -> None:
    registry = create_registry(timestamp=FIXED)
    fixtures = (
        ("a.json", "sample-a", "1505", "DP32G030"),
        ("b.json", "sample-b", "1605", "PY32F030"),
        ("c.json", "sample-c", "1705", "PY32F071"),
    )
    for name, device, value, mcu in fixtures:
        registry = add_evidence_bundle(
            registry,
            _candidate_bundle(tmp_path, name, device, value, mcu),
            timestamp=FIXED,
        ).registry
    candidate = propose_discriminator(
        registry, offset=0, length=2, driver_id="quansheng", timestamp=FIXED
    ).candidates[0]
    assert candidate.device_count == 3
    assert candidate.status is CandidateStatus.CORRELATED
    assert candidate.status is not CandidateStatus.VERIFIED
    assert candidate.declared_hardware_correlations


def test_conflict_forces_candidate_contradicted(tmp_path: Path) -> None:
    bundle = _declared_bundle(
        tmp_path,
        "conflict-candidate.json",
        "sample-a",
        [
            {"field": "mcu", "value": "DP32G030"},
            {"field": "mcu", "value": "PY32F030"},
        ],
    )
    registry = add_evidence_bundle(
        create_registry(timestamp=FIXED), bundle, timestamp=FIXED
    ).registry
    candidate = propose_discriminator(
        registry, offset=0, length=2, driver_id="quansheng", timestamp=FIXED
    ).candidates[0]
    assert candidate.status is CandidateStatus.CONTRADICTED


def test_withdrawn_declaration_does_not_create_conflict(tmp_path: Path) -> None:
    bundle = _declared_bundle(
        tmp_path,
        "withdrawn.json",
        "sample-a",
        [{"field": "mcu", "value": "DP32G030"}],
    )
    raw = json.loads(bundle.read_text())
    withdrawn = dict(raw["declarations"][0])
    withdrawn["value"] = "PY32F030"
    withdrawn["verification_status"] = "withdrawn"
    raw["declarations"].append(withdrawn)
    bundle.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    registry = add_evidence_bundle(
        create_registry(timestamp=FIXED), bundle, timestamp=FIXED
    ).registry
    assert not detect_conflicts(registry)


def test_contribution_is_byte_deterministic_and_import_is_explicit(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    first_id = create_contribution((bundle,), first, notes="fixture")
    second_id = create_contribution((bundle,), second, notes="fixture")
    assert first_id == second_id
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert all(info.date_time == (2020, 1, 1, 0, 0, 0) for info in archive.infolist())
    plan = plan_contribution_import(create_registry(timestamp=FIXED), first, timestamp=FIXED)
    assert plan.mutation.imported_bundle_ids


def test_contribution_declarations_require_manual_review(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    archive = tmp_path / "declared.zip"
    declaration = {
        "confidence": "user-supplied",
        "device_label": "sample-a",
        "field": "mcu",
        "notes": "marking inspected",
        "source": "user-input",
        "timestamp": FIXED,
        "value": "DP32G030",
        "verification_status": "self-inspected",
    }
    create_contribution((bundle,), archive, declarations=(declaration,))
    review = review_contribution(archive)
    assert review.classification == "requires-manual-review"
    assert review.safe
    plan = plan_contribution_import(create_registry(timestamp=FIXED), archive, timestamp=FIXED)
    assert plan.mutation.registry.declarations[0].value == "DP32G030"


def _malicious_zip(path: Path, name: str, mode: int = 0o100644) -> None:
    info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = mode << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, b"unsafe")


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("../escape.json", "unsafe_archive_path"),
        ("/absolute.json", "unsafe_archive_path"),
        ("firmware.bin", "forbidden_file_type"),
    ],
)
def test_contribution_rejects_unsafe_paths_and_firmware(
    tmp_path: Path, name: str, reason: str
) -> None:
    path = tmp_path / "unsafe.zip"
    _malicious_zip(path, name)
    review = review_contribution(path)
    assert review.classification == "rejected"
    assert any(reason in error for error in review.errors)


def test_contribution_rejects_executable_and_symlink(tmp_path: Path) -> None:
    executable = tmp_path / "executable.zip"
    _malicious_zip(executable, "script.txt", 0o100755)
    assert any("executable" in item for item in review_contribution(executable).errors)
    symlink = tmp_path / "symlink.zip"
    _malicious_zip(symlink, "link", stat.S_IFLNK | 0o777)
    assert any("symlink" in item for item in review_contribution(symlink).errors)


def test_contribution_rejects_duplicate_members(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", "{}")
            archive.writestr("manifest.json", "{}")
    assert "duplicate_archive_member" in review_contribution(path).errors


def test_cli_json_and_import_approval_contract(tmp_path: Path) -> None:
    runner = CliRunner()
    registry = tmp_path / "registry.json"
    assert runner.invoke(app, ["registry-create", str(registry), "--json"]).exit_code == 0
    bundle = _bundle(tmp_path)
    archive = tmp_path / "contribution.zip"
    create_contribution((bundle,), archive)
    dry = runner.invoke(
        app,
        ["registry-import-contribution", str(registry), str(archive), "--dry-run", "--json"],
    )
    assert dry.exit_code == 0
    assert json.loads(dry.stdout)["mutation_performed"] is False
    denied = runner.invoke(
        app,
        ["registry-import-contribution", str(registry), str(archive), "--json"],
    )
    assert denied.exit_code == 2
    assert json.loads(denied.stdout)["mutation_performed"] is False
    assert "--yes" in denied.stderr


def test_public_registry_api_and_command_snapshot() -> None:
    from qsidentify.registry import (
        EvidenceRegistry,
        add_evidence_bundle,
        analyze_registry,
        create_registry,
        load_registry,
        validate_registry,
    )

    assert EvidenceRegistry.__dataclass_params__.frozen is True
    assert callable(add_evidence_bundle)
    assert callable(analyze_registry)
    assert callable(create_registry)
    assert callable(load_registry)
    assert callable(validate_registry)
    inventory = Path("src/qsidentify/drivers/quansheng/data/command_inventory.json")
    import hashlib

    assert hashlib.sha256(inventory.read_bytes()).hexdigest() == APPROVED_COMMAND_INVENTORY_SHA256


def test_registry_modules_have_no_transport_network_or_catalog_mutation() -> None:
    registry_source = Path("src/qsidentify/evidence_registry.py").read_text()
    contribution_source = Path("src/qsidentify/contribution.py").read_text()
    combined = registry_source + contribution_source
    assert "from .transport" not in combined
    assert "import requests" not in combined
    assert "urlopen" not in combined
    assert "firmware_catalog.json" not in combined
    assert "hardware_catalog.json" not in combined
    assert "VERIFIED" in registry_source
    assert "automatic_verified_status_forbidden" in registry_source
