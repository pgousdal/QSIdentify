from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qsidentify.capture import read_capture
from qsidentify.cli import app
from qsidentify.evidence import (
    EvidenceError,
    analyze_stability,
    build_fingerprint,
    evidence_report,
    export_bundle,
    load_command_inventory,
    load_discriminators,
    load_probe_definitions,
    validate_bundle,
)

FIXTURES = Path("tests/fixtures/captures")
PHYSICAL = FIXTURES / "uv-k5-8-2.01.36.json"


def test_command_inventory_matches_runtime_allowlist() -> None:
    inventory = load_command_inventory()
    allowed = [item for item in inventory if item.allowlisted]
    assert [(item.command_id, item.minimum_request) for item in allowed] == [
        ("0x0514", "140504006a395764")
    ]
    assert all(item.read_only and item.provenance for item in allowed)


def test_unknown_commands_are_not_allowlisted() -> None:
    unavailable = [
        item for item in load_command_inventory() if item.command_id.startswith("unavailable:")
    ]
    assert unavailable
    assert all(not item.allowlisted and item.safety_class == "unknown" for item in unavailable)


def test_probe_definitions_are_bounded_and_allowlisted() -> None:
    probes = load_probe_definitions()
    default = next(item for item in probes if item.enabled_by_default)
    assert default.id == "firmware-identification"
    assert default.commands == ("0x0514",)
    assert all(item.repeat_count <= 20 for item in probes)


def test_physical_fixture_stability_and_fingerprint() -> None:
    capture = read_capture(PHYSICAL)
    stability = analyze_stability((capture, capture))
    assert stability.firmware_strings == ("2.01.36",)
    assert stability.variable_positions == ()
    first = build_fingerprint((capture, capture))
    second = build_fingerprint((replace(capture, created_utc="2030-01-01T00:00:00+00:00"),) * 2)
    assert first.fingerprint_id == second.fingerprint_id
    assert first.fingerprint_id.startswith("qsfingerprint:v1:sha256:")


def test_stability_marks_changed_payload_byte_variable() -> None:
    capture = read_capture(PHYSICAL)
    candidate = next(item for item in capture.candidate_frames if item.decoded is not None)
    changed_payload = candidate.decoded.payload[:-1] + bytes([candidate.decoded.payload[-1] ^ 1])
    changed_candidate = replace(
        candidate, decoded=replace(candidate.decoded, payload=changed_payload)
    )
    changed = replace(capture, candidate_frames=(changed_candidate,))
    stability = analyze_stability((capture, changed))
    assert len(changed_payload) - 1 in stability.variable_positions


def test_report_never_maps_candidate_to_hardware() -> None:
    report = evidence_report((read_capture(PHYSICAL),))
    assert report["confidence"]["mcu"] == "unknown"
    assert report["confidence"]["hardware_revision"] == "unknown"
    assert all(item["experimental"] for item in report["candidate_discriminators"])
    assert all(not item["maps_to"] for item in load_discriminators())


def test_user_labels_are_scoped_user_evidence() -> None:
    capture = read_capture(PHYSICAL)
    labelled = replace(capture, capture_metadata={"marketed_model": "UV-K5(8)"})
    report = evidence_report((labelled,))
    assert report["user_supplied_labels"] == {"marketed_model": "UV-K5(8)"}
    assert report["confidence"]["marketed_model"] == "user-supplied"
    assert report["confidence"]["mcu"] == "unknown"


def test_bundle_is_sanitized_deterministic_and_valid(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    export_bundle((PHYSICAL,), first, "sanitized physical fixture")
    export_bundle((PHYSICAL,), second, "sanitized physical fixture")
    assert first.read_bytes() == second.read_bytes()
    ok, errors = validate_bundle(first)
    assert ok and not errors
    text = first.read_text()
    assert '"sanitized": true' in text
    assert "/home/" not in text


def test_malformed_bundle_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"bundle_schema_version": 99}), encoding="utf-8")
    assert validate_bundle(path)[0] is False


def test_fingerprint_rejects_mixed_drivers() -> None:
    capture = read_capture(PHYSICAL)
    with pytest.raises(EvidenceError, match="different drivers"):
        build_fingerprint((capture, replace(capture, driver_id="other")))


def test_evidence_cli_json_contracts() -> None:
    runner = CliRunner()
    listed = runner.invoke(app, ["command-list", "--json"])
    assert listed.exit_code == 0
    assert json.loads(listed.stdout)["commands"][0]["command_id"] == "0x0514"
    report = runner.invoke(app, ["evidence-report", str(PHYSICAL), "--json"])
    assert report.exit_code == 0
    assert json.loads(report.stdout)["observed"]["firmware_strings"] == ["2.01.36"]


def test_unavailable_experimental_probe_refused_without_serial_io() -> None:
    result = CliRunner().invoke(
        app,
        ["evidence-probe", "/dev/does-not-matter", "--probe", "bootloader-identification"],
    )
    assert result.exit_code == 2
    assert "Unavailable" in result.stderr
