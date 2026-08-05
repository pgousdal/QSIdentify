import hashlib
import inspect
import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qsidentify import IdentificationResult, identify
from qsidentify.capture import read_capture, write_capture
from qsidentify.cli import app
from qsidentify.drivers import DRIVER_API_VERSION, DriverInfo, get_driver
from qsidentify.drivers.quansheng import QuanshengDriver
from qsidentify.drivers.registry import DriverRegistry
from qsidentify.fixtures import validate_fixture_manifest
from qsidentify.hardening import (
    NORMALIZED_CREATED_UTC,
    ValidationStatus,
    audit_results,
    capture_digest,
    machine_metadata,
    sanitize_capture,
    validate_capture,
)

FIXTURES = Path("tests/fixtures")


def test_fixture_manifest_and_physical_provenance() -> None:
    result = validate_fixture_manifest(FIXTURES)
    assert result.ok, result.errors
    capture = read_capture(FIXTURES / "captures/uv-k5-8-2.01.36.json")
    assert capture.report.reported_version == "2.01.36"
    assert capture.checksum_status is not None
    assert capture.checksum_status.value == "accepted-legacy-ff-ff"
    assert capture.capture_metadata["fixture_kind"] == "sanitized-physical-capture"
    assert not machine_metadata(capture)


@pytest.mark.parametrize("schema", ["schema-v1.json", "schema-v2.json", "valid-firmware.json"])
def test_sanitization_preserves_protocol_bytes(schema: str) -> None:
    original = read_capture(FIXTURES / "captures" / schema)
    sanitized, changes = sanitize_capture(original)
    assert sanitized.schema_version == 3
    assert sanitized.raw_response_hex == original.raw_response_hex
    assert sanitized.encoded_transmitted_frame_hex == original.encoded_transmitted_frame_hex
    assert sanitized.logical_request_payload_hex == original.logical_request_payload_hex
    assert b"".join(chunk.data for chunk in sanitized.read_chunks) == b"".join(
        chunk.data for chunk in original.read_chunks
    )
    assert sanitized.created_utc == NORMALIZED_CREATED_UTC
    assert sanitized.port.serial_number is None
    assert tuple(sorted(changes)) == changes


def test_sanitization_is_deterministic(tmp_path: Path) -> None:
    original = read_capture(FIXTURES / "captures/schema-v2.json")
    first, _ = sanitize_capture(original)
    second, _ = sanitize_capture(original)
    assert first.to_dict() == second.to_dict()
    path = tmp_path / "capture.json"
    write_capture(path, first)
    assert validate_capture(path).status is ValidationStatus.VALID


def test_validation_statuses_and_digest(tmp_path: Path) -> None:
    valid = FIXTURES / "captures/valid-firmware.json"
    assert validate_capture(valid).status is ValidationStatus.VALID
    capture = read_capture(valid)
    assert (
        capture_digest(capture)
        == hashlib.sha256(
            (json.dumps(capture.to_dict(), indent=2, sort_keys=True) + "\n").encode()
        ).hexdigest()
    )
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 99}')
    assert validate_capture(bad).status is ValidationStatus.UNSUPPORTED_SCHEMA
    bad.write_text("{")
    assert validate_capture(bad).status is ValidationStatus.INVALID


def test_capture_cli_json_and_collision(tmp_path: Path) -> None:
    runner = CliRunner()
    source = FIXTURES / "captures/valid-firmware.json"
    inspect_result = runner.invoke(app, ["capture-inspect", str(source), "--json"])
    validate_result = runner.invoke(app, ["capture-validate", str(source), "--json"])
    collision = runner.invoke(app, ["capture-sanitize", str(source), str(source)])
    assert inspect_result.exit_code == 0 and json.loads(inspect_result.stdout)["sanitized"]
    assert validate_result.exit_code == 0
    assert json.loads(validate_result.stdout)["captures"][0]["status"] == "valid"
    assert collision.exit_code == 3 and "refused" in collision.stderr


def test_machine_readable_contract_commands() -> None:
    runner = CliRunner()
    commands = [
        ["drivers", "--json"],
        ["driver-info", "quansheng", "--json"],
        ["release-info", "--json"],
        ["audit", "--json"],
        ["fixture-validate", "--json"],
    ]
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.output
        json.loads(result.stdout)
        assert result.stderr == ""


def test_public_api_contract_is_explicit_and_immutable() -> None:
    assert list(inspect.signature(identify).parameters) == [
        "device",
        "driver_id",
        "baud_rate",
        "timeout",
        "idle_timeout",
        "settle_delay",
        "dtr",
        "rts",
    ]
    assert list(IdentificationResult.__dataclass_fields__) == ["driver", "report"]
    assert IdentificationResult.__dataclass_params__.frozen


class IncompatibleDriver(QuanshengDriver):
    @property
    def info(self) -> DriverInfo:
        return replace(super().info, id="incompatible", api_version=DRIVER_API_VERSION + 1)


def test_driver_api_version_is_distinct_and_enforced() -> None:
    driver = get_driver("quansheng")
    assert DRIVER_API_VERSION == 1
    assert driver.info.version == "1.0"
    assert driver.info.api_version == DRIVER_API_VERSION
    with pytest.raises(ValueError, match="required API"):
        DriverRegistry((IncompatibleDriver(),))


def test_offline_audit_contract() -> None:
    checks = audit_results()
    assert checks
    assert all(check["ok"] and check["offline"] for check in checks)
